use crate::{BenchmarkAccessor, TableDefinition};
use proof_of_sql::base::{
    commitment::Commitment,
    database::{OwnedColumn, OwnedTable, OwnedTableError, TableRef},
};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;

#[derive(Debug)]
pub enum ParquetExportError {
    Io(std::io::Error),
    Arrow(arrow::error::ArrowError),
    Parquet(parquet::errors::ParquetError),
    OwnedTable(OwnedTableError),
    MissingTable { table: String },
}

impl From<std::io::Error> for ParquetExportError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<arrow::error::ArrowError> for ParquetExportError {
    fn from(err: arrow::error::ArrowError) -> Self {
        Self::Arrow(err)
    }
}

impl From<parquet::errors::ParquetError> for ParquetExportError {
    fn from(err: parquet::errors::ParquetError) -> Self {
        Self::Parquet(err)
    }
}

impl From<OwnedTableError> for ParquetExportError {
    fn from(err: OwnedTableError) -> Self {
        Self::OwnedTable(err)
    }
}

fn sanitize_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "table".to_string()
    } else {
        out
    }
}

fn table_ref_filename(table_ref: &TableRef) -> String {
    sanitize_component(&table_ref.to_string()) + ".parquet"
}

fn record_batch_for_table<'a, C: Commitment>(
    accessor: &BenchmarkAccessor<'a, C>,
    table_ref: &TableRef,
) -> Result<RecordBatch, ParquetExportError> {
    let columns = accessor
        .table_columns(table_ref)
        .ok_or_else(|| ParquetExportError::MissingTable {
            table: table_ref.to_string(),
        })?;

    let owned_table = OwnedTable::try_from_iter(
        columns
            .into_iter()
            .map(|(ident, column)| (ident, OwnedColumn::from(&column))),
    )?;

    Ok(RecordBatch::try_from(owned_table)?)
}

pub fn export_tables_to_parquet<'a, C: Commitment>(
    accessor: &BenchmarkAccessor<'a, C>,
    tables: &[TableDefinition],
    output_dir: impl AsRef<Path>,
    query_name: &str,
) -> Result<Vec<PathBuf>, ParquetExportError> {
    let query_dir = output_dir.as_ref().join(sanitize_component(query_name));
    fs::create_dir_all(&query_dir)?;

    let mut outputs = Vec::with_capacity(tables.len());
    for table in tables {
        let table_ref = TableRef::from_names(None, table.name);
        let file_path = query_dir.join(table_ref_filename(&table_ref));
        if file_path.exists() {
            outputs.push(file_path);
            continue;
        }

        let batch = record_batch_for_table(accessor, &table_ref)?;
        let file = File::create(&file_path)?;
        let mut writer = ArrowWriter::try_new(file, batch.schema(), None)?;
        writer.write(&batch)?;
        writer.close()?;
        outputs.push(file_path);
    }

    Ok(outputs)
}
