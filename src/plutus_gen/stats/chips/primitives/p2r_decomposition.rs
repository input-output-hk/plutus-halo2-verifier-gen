use super::super::{Argument, Chip, Column, LookupTable, RotationSet, ScalarExpression};

/// Power-of-2 range decomposition chip (NativeChip + Pow2RangeChip) for `nr_pow2range_cols = 1`
///
/// Column layout:
///   advice = arch.nr_pow2range_cols, whose default value is 1 in zk_stdlib config.
///   fixed  = 1: tag column
///   table  = 2: tag & value
///
/// Pow2RangeChip calls meta.lookup once per val_col arguments, each with (Fixed_tag, t_tag) and
/// (Selector*Advice, t_val) pairs.
pub(crate) struct P2RDecomposition;

impl Chip for P2RDecomposition {
    fn advice_columns() -> Vec<Column> {
        vec![Column::advice(RotationSet::curr(), false)]
    }

    fn extra_columns() -> Vec<Column> {
        vec![
            Column::exclusive_fixed(RotationSet::curr(), false), // tag_col (exclusive fixed)
            Column::complex_selector(),                          // q_pow2range
        ]
    }

    fn lookup_tables() -> Vec<LookupTable> {
        vec![LookupTable::register("pow2range".to_string(), 2)]
    }

    // vec![(tag, t_tag), (sel * val, t_val)] — 2 ScalarExpressions per argument
    fn lookup_args() -> Vec<Argument> {
        vec![vec![
            ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0),
            ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 0, 0),
        ]]
    }
}
