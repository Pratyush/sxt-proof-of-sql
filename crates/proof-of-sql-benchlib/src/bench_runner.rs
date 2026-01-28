use crate::{export_tables_to_parquet, generate_random_columns, BenchmarkAccessor, QueryEntry};
use ark_bn254::G1Affine as Bn254G1Affine;
use ark_serialize::Validate;
use bumpalo::Bump;
use datafusion::config::ConfigOptions;
use halo2curves::{
    bn256::{Fq as Halo2Bn256Fq, G1Affine as Halo2Bn256G1Affine},
    serde::SerdeObject,
};
use nova_snark::{
    provider::{
        bn256_grumpkin::bn256::Affine,
        hyperkzg::{CommitmentEngine, CommitmentKey, EvaluationEngine, VerifierKey},
    },
    traits::{commitment::CommitmentEngineTrait, evaluation::EvaluationEngineTrait},
};
use proof_of_sql::{
    base::{commitment::CommitmentEvaluationProof, database::TableRef},
    proof_primitive::hyperkzg::{
        deserialize_flat_compressed_hyperkzg_public_setup_from_reader,
        nova_commitment_key_to_hyperkzg_public_setup, HyperKZGCommitmentEvaluationProof,
        HyperKZGEngine,
    },
    sql::proof::VerifiableQueryResult,
};
use proof_of_sql_planner::sql_to_proof_plans;
use rand::{rngs::StdRng, SeedableRng};
use sqlparser::dialect::GenericDialect;
use std::{
    fs::File,
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Debug, Clone)]
pub struct BenchOptions {
    pub iterations: usize,
    pub table_size: usize,
    pub rand_seed: Option<u64>,
    pub parquet_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct BenchResult {
    pub commitment_scheme: &'static str,
    pub query: String,
    pub table_size: usize,
    pub iteration: usize,
    pub generate_proof_ms: u128,
    pub verify_proof_ms: u128,
    pub num_query_results: usize,
}

#[derive(Debug, Clone)]
pub struct BenchRunOutput {
    pub results: Vec<BenchResult>,
    pub parquet_paths: Vec<PathBuf>,
}

#[derive(Debug)]
pub enum BenchRunError {
    Io(std::io::Error),
    SqlParse(String),
    Planning(String),
    Proof(String),
    Verify(String),
    Setup(String),
    Parquet(String),
}

impl From<std::io::Error> for BenchRunError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

fn rng(options: &BenchOptions) -> StdRng {
    if let Some(seed) = options.rand_seed {
        StdRng::seed_from_u64(seed)
    } else {
        StdRng::from_entropy()
    }
}

fn table_size_for_query(table_size: usize, query: &str) -> usize {
    if query == "Join" || query == "Union All" {
        table_size.div_ceil(2)
    } else {
        table_size
    }
}

/// Converts an Arkworks BN254 G1 Affine point to a Halo2 BN256 G1 Affine point.
fn convert_to_halo2_bn256_g1_affine(point: &Bn254G1Affine) -> Halo2Bn256G1Affine {
    if point.infinity {
        return Halo2Bn256G1Affine::default();
    }

    let x_bytes = bytemuck::cast::<[u64; 4], [u8; 32]>(point.x.0 .0);
    let y_bytes = bytemuck::cast::<[u64; 4], [u8; 32]>(point.y.0 .0);

    Halo2Bn256G1Affine {
        x: Halo2Bn256Fq::from_raw_bytes_unchecked(&x_bytes),
        y: Halo2Bn256Fq::from_raw_bytes_unchecked(&y_bytes),
    }
}

fn load_hyperkzg_setup(
    options: &BenchOptions,
    ppot_path: Option<&Path>,
) -> Result<(Vec<Bn254G1Affine>, VerifierKey<HyperKZGEngine>), BenchRunError> {
    let (prover_setup, vk) = if let Some(ppot_file_path) = ppot_path {
        let file = File::open(ppot_file_path)?;
        let prover_setup =
            deserialize_flat_compressed_hyperkzg_public_setup_from_reader(&file, Validate::Yes)
                .map_err(|err| BenchRunError::Setup(err.to_string()))?;

        let ck: CommitmentKey<HyperKZGEngine> = CommitmentKey::new(
            prover_setup
                .iter()
                .map(convert_to_halo2_bn256_g1_affine)
                .collect(),
            Affine::default(),
            halo2curves::bn256::G2Affine::default(),
        );
        let (_, vk) = EvaluationEngine::setup(&ck);

        (prover_setup, vk)
    } else {
        let ck: CommitmentKey<HyperKZGEngine> =
            CommitmentEngine::setup(b"bench", options.table_size);
        let (_, vk) = EvaluationEngine::setup(&ck);
        let prover_setup = nova_commitment_key_to_hyperkzg_public_setup(&ck);
        (prover_setup, vk)
    };

    Ok((prover_setup, vk))
}

pub fn run_hyperkzg_bench(
    queries: &[QueryEntry],
    options: &BenchOptions,
    ppot_path: Option<&Path>,
) -> Result<BenchRunOutput, BenchRunError> {
    let (prover_setup, vk) = load_hyperkzg_setup(options, ppot_path)?;
    let prover_setup_slice = prover_setup.as_slice();
    let verifier_setup = &vk;

    let mut results = Vec::new();
    let mut parquet_paths = Vec::new();
    let mut accessor: BenchmarkAccessor<'_, <HyperKZGCommitmentEvaluationProof as CommitmentEvaluationProof>::Commitment> =
        BenchmarkAccessor::default();

    let alloc = Bump::new();
    let mut rng = rng(options);

    for (query, sql, tables, params) in queries {
        // Build tables
        for table in tables {
            accessor.insert_table(
                TableRef::from_names(None, table.name),
                &generate_random_columns(
                    &alloc,
                    &mut rng,
                    table.columns.as_slice(),
                    table_size_for_query(options.table_size, query),
                ),
                &prover_setup_slice,
            );
        }

        if let Some(parquet_dir) = &options.parquet_dir {
            let outputs = export_tables_to_parquet(&accessor, tables, parquet_dir, query)
                .map_err(|err| BenchRunError::Parquet(format!("{err:?}")))?;
            parquet_paths.extend(outputs);
        }

        let config = ConfigOptions::default();
        let statements = sqlparser::parser::Parser::parse_sql(&GenericDialect {}, sql)
            .map_err(|err| BenchRunError::SqlParse(err.to_string()))?;
        let plans = sql_to_proof_plans(&statements, &accessor, &config)
            .map_err(|err| BenchRunError::Planning(err.to_string()))?;

        for plan in plans {
            for i in 0..options.iterations {
                let time = Instant::now();
                let res = VerifiableQueryResult::<HyperKZGCommitmentEvaluationProof>::new(
                    &plan,
                    &accessor,
                    &prover_setup_slice,
                    params,
                )
                .map_err(|err| BenchRunError::Proof(err.to_string()))?;
                let generate_proof_elapsed = time.elapsed().as_millis();

                let num_query_results = res.result.num_rows();

                let time = Instant::now();
                res.verify(&plan, &accessor, &verifier_setup, params)
                    .map_err(|err| BenchRunError::Verify(err.to_string()))?;
                let verify_elapsed = time.elapsed().as_millis();

                results.push(BenchResult {
                    commitment_scheme: "HyperKZG",
                    query: (*query).to_string(),
                    table_size: options.table_size,
                    iteration: i,
                    generate_proof_ms: generate_proof_elapsed,
                    verify_proof_ms: verify_elapsed,
                    num_query_results,
                });
            }
        }
    }

    Ok(BenchRunOutput {
        results,
        parquet_paths,
    })
}
