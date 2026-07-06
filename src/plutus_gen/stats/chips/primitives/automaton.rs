use crate::plutus_gen::SupportedChips;

use super::super::{Argument, Chip, Column, LookupTable, RotationSet, ScalarExpression};

/// Static automaton parsing via a fixed lookup table.
pub(crate) struct Automaton;

impl Chip for Automaton {
    fn advice_columns() -> Vec<Column> {
        vec![
            Column::advice(
                RotationSet::new(false, false, true, true, false, false, false),
                true,
            ),
            Column::advice(RotationSet::curr(), true),
            Column::advice(RotationSet::curr(), true),
            Column::advice(RotationSet::curr(), true),
            Column::advice(RotationSet::curr(), true),
            Column::advice(RotationSet::curr(), true),
        ]
    }

    fn extra_columns() -> Vec<Column> {
        vec![
            Column::complex_selector(), // q_automaton
        ]
    }

    fn lookup_args() -> Vec<Argument> {
        vec![
            vec![
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0),
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0),
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0),
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0),
            ],
            vec![
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0),
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0),
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0),
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0),
            ],
        ]
    }

    fn lookup_tables() -> Vec<LookupTable> {
        vec![LookupTable::register("scanner".to_string(), 4)]
    }

    // NR_POW2RANGE_COLS set to 1 to follow zk_stdlib
    fn nr_pow2range() -> usize {
        1
    }

    fn chip_deps() -> Vec<crate::plutus_gen::SupportedChips> {
        vec![SupportedChips::Native]
    }
}
