use crate::plutus_gen::SupportedChips;

use super::super::{Argument, Chip, Column, LookupTable, RotationSet, ScalarExpression};

/// This module contains the `Base64Chip`, which implements Base64 decoding
/// instructions.
pub(crate) struct Base64;

impl Chip for Base64 {
    fn advice_columns() -> Vec<Column> {
        vec![
            Column::advice(RotationSet::curr(), false),
            Column::advice(RotationSet::curr(), false),
            Column::advice(RotationSet::curr(), false),
            // Column::advice(RotationSet::default(), false),
        ]
    }

    fn extra_columns() -> Vec<Column> {
        vec![
            Column::complex_selector(), // lookup_sel
        ]
    }

    fn lookup_args() -> Vec<Argument> {
        vec![vec![
            ScalarExpression::lookup_expression(2, 1, 1, 3, 0, 3, 3),
            ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0),
        ]]
    }

    fn lookup_tables() -> Vec<LookupTable> {
        vec![LookupTable::register("base64".to_string(), 2)]
    }

    // NR_POW2RANGE_COLS set to 1 to follow zk_stdlib
    fn nr_pow2range() -> usize {
        1
    }

    fn chip_deps() -> Vec<crate::plutus_gen::SupportedChips> {
        vec![SupportedChips::Native]
    }
}
