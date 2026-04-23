use bumpalo::Bump;
use proof_of_sql::base::{
    database::{Column, ColumnType},
    scalar::Scalar,
};
use rand::Rng;
use sqlparser::ast::Ident;

pub type OptionalRandBound = Option<fn(usize) -> i64>;

/// Per-column deterministic override callback.
///
/// Given `(table_name, column_name, num_rows)`, return `Some(values)` to replace the
/// column's generated data with the provided `i64` slice (must have exactly `num_rows`
/// entries), or `None` to fall back to the RNG bound from the `ColumnDefinition`.
/// Used by benches that need to compare the *same* row shape across systems
/// (e.g. PK/FK join cardinality parity) without touching every call site.
pub type ColumnOverride = fn(&str, &str, usize) -> Option<Vec<i64>>;

/// # Panics
///
/// Will panic if:
/// - An unsupported `ColumnType` is encountered, triggering a panic in the `todo!()` macro.
#[expect(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]
pub fn generate_random_columns<'a, S: Scalar>(
    alloc: &'a Bump,
    rng: &mut impl Rng,
    columns: &[(&str, ColumnType, OptionalRandBound)],
    num_rows: usize,
) -> Vec<(Ident, Column<'a, S>)> {
    generate_columns_with_override(alloc, rng, "", columns, num_rows, None)
}

/// Same as `generate_random_columns`, but checks `column_override` first for each column
/// and uses the override's `Vec<i64>` when it returns `Some`. Only `BigInt` columns are
/// supported for override; other types panic if override is present.
#[expect(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]
pub fn generate_columns_with_override<'a, S: Scalar>(
    alloc: &'a Bump,
    rng: &mut impl Rng,
    table_name: &str,
    columns: &[(&str, ColumnType, OptionalRandBound)],
    num_rows: usize,
    column_override: Option<ColumnOverride>,
) -> Vec<(Ident, Column<'a, S>)> {
    columns
        .iter()
        .map(|(id, ty, bound)| {
            if let Some(overrider) = column_override {
                if let Some(values) = overrider(table_name, id, num_rows) {
                    assert_eq!(
                        values.len(),
                        num_rows,
                        "column_override for `{table_name}.{id}` must return exactly num_rows values"
                    );
                    assert!(
                        matches!(ty, ColumnType::BigInt),
                        "column_override only supports BigInt columns; `{table_name}.{id}` is {ty:?}"
                    );
                    let slice = alloc.alloc_slice_fill_iter(values.into_iter());
                    return (Ident::new(*id), Column::BigInt(slice));
                }
            }
            (
                Ident::new(*id),
                match (ty, bound) {
                    (ColumnType::Boolean, _) => {
                        Column::Boolean(alloc.alloc_slice_fill_with(num_rows, |_| rng.gen()))
                    }
                    (ColumnType::Uint8, None) => {
                        Column::Uint8(alloc.alloc_slice_fill_with(num_rows, |_| rng.gen()))
                    }
                    (ColumnType::Uint8, Some(b)) => {
                        let clamped_b_value = b(num_rows).clamp(0, i64::from(u8::MAX)) as u8;
                        Column::Uint8(alloc.alloc_slice_fill_with(num_rows, |_| {
                            rng.gen_range(0..=clamped_b_value)
                        }))
                    }
                    (ColumnType::TinyInt, None) => {
                        Column::TinyInt(alloc.alloc_slice_fill_with(num_rows, |_| rng.gen()))
                    }
                    (ColumnType::TinyInt, Some(b)) => {
                        let clamped_b_value =
                            b(num_rows).clamp(i64::from(i8::MIN), i64::from(i8::MAX)) as i8;
                        Column::TinyInt(alloc.alloc_slice_fill_with(num_rows, |_| {
                            rng.gen_range(-clamped_b_value..=clamped_b_value)
                        }))
                    }
                    (ColumnType::SmallInt, None) => {
                        Column::SmallInt(alloc.alloc_slice_fill_with(num_rows, |_| rng.gen()))
                    }
                    (ColumnType::SmallInt, Some(b)) => {
                        let clamped_b_value =
                            b(num_rows).clamp(i64::from(i16::MIN), i64::from(i16::MAX)) as i16;
                        Column::SmallInt(alloc.alloc_slice_fill_with(num_rows, |_| {
                            rng.gen_range(-clamped_b_value..=clamped_b_value)
                        }))
                    }
                    (ColumnType::Int, None) => {
                        Column::Int(alloc.alloc_slice_fill_with(num_rows, |_| rng.gen()))
                    }
                    (ColumnType::Int, Some(b)) => {
                        let clamped_b_value =
                            b(num_rows).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
                        Column::Int(alloc.alloc_slice_fill_with(num_rows, |_| {
                            rng.gen_range(-clamped_b_value..=clamped_b_value)
                        }))
                    }
                    (ColumnType::BigInt, None) => {
                        Column::BigInt(alloc.alloc_slice_fill_with(num_rows, |_| rng.gen()))
                    }
                    (ColumnType::BigInt, Some(b)) => {
                        Column::BigInt(alloc.alloc_slice_fill_with(num_rows, |_| {
                            rng.gen_range(-b(num_rows)..=b(num_rows))
                        }))
                    }
                    (ColumnType::Int128, None) => {
                        Column::Int128(alloc.alloc_slice_fill_with(num_rows, |_| rng.gen()))
                    }
                    (ColumnType::Int128, Some(b)) => {
                        Column::Int128(alloc.alloc_slice_fill_with(num_rows, |_| {
                            rng.gen_range((i128::from(-b(num_rows)))..=(i128::from(b(num_rows))))
                        }))
                    }
                    (ColumnType::VarChar, _) => {
                        let strs = alloc.alloc_slice_fill_with(num_rows, |_| {
                            let len = rng
                                .gen_range(0..=bound.map(|b| b(num_rows) as usize).unwrap_or(10));
                            alloc.alloc_str(
                                &rng.sample_iter(&rand::distributions::Alphanumeric)
                                    .take(len)
                                    .map(char::from)
                                    .collect::<String>(),
                            ) as &str
                        });
                        Column::VarChar((
                            strs,
                            alloc.alloc_slice_fill_iter(strs.iter().map(|&s| Into::into(s))),
                        ))
                    }
                    (ColumnType::Scalar, _) => {
                        let strs = alloc.alloc_slice_fill_with(num_rows, |_| {
                            let len = rng
                                .gen_range(0..=bound.map(|b| b(num_rows) as usize).unwrap_or(10));
                            alloc.alloc_str(
                                &rng.sample_iter(&rand::distributions::Alphanumeric)
                                    .take(len)
                                    .map(char::from)
                                    .collect::<String>(),
                            ) as &str
                        });
                        Column::Scalar(
                            alloc.alloc_slice_fill_iter(strs.iter().map(|&s| Into::into(s))),
                        )
                    }
                    (ColumnType::Decimal75(p, s), _) => {
                        let strs = alloc.alloc_slice_fill_with(num_rows, |_| {
                            let len = rng
                                .gen_range(0..=bound.map(|b| b(num_rows) as usize).unwrap_or(10));
                            alloc.alloc_str(
                                &rng.sample_iter(&rand::distributions::Alphanumeric)
                                    .take(len)
                                    .map(char::from)
                                    .collect::<String>(),
                            ) as &str
                        });
                        Column::Decimal75(
                            *p,
                            *s,
                            alloc.alloc_slice_fill_iter(strs.iter().map(|&s| Into::into(s))),
                        )
                    }
                    (ColumnType::TimestampTZ(u, z), None) => Column::TimestampTZ(
                        *u,
                        *z,
                        alloc.alloc_slice_fill_with(num_rows, |_| rng.gen()),
                    ),
                    (ColumnType::TimestampTZ(u, z), Some(b)) => Column::TimestampTZ(
                        *u,
                        *z,
                        alloc.alloc_slice_fill_with(num_rows, |_| {
                            rng.gen_range(-b(num_rows)..=b(num_rows))
                        }),
                    ),
                    _ => todo!(),
                },
            )
        })
        .collect()
}
