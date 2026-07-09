use super::super::super::{Argument, Chip, Column, RotationSet, ScalarExpression, SupportedChips};

/// Twisted Edwards chip for Jubjub
pub(crate) struct EdwardsJubjub;

impl Chip for EdwardsJubjub {
    fn advice_columns() -> Vec<Column> {
        let current_next = RotationSet::new(false, false, true, true, false, false, false);
        vec![
            Column::advice(current_next, true),
            Column::advice(current_next, true),
            Column::advice(RotationSet::curr(), true),
            Column::advice(RotationSet::curr(), true),
            Column::advice(RotationSet::curr(), true),
            Column::advice(RotationSet::curr(), true),
            Column::advice(RotationSet::curr(), true),
            Column::advice(RotationSet::curr(), false),
            Column::advice(RotationSet::curr(), false),
        ]
    }

    fn extra_columns() -> Vec<Column> {
        vec![
            Column::selector(), // q_double
            Column::selector(), // q_cond_add
            Column::selector(), // q_mem
        ]
    }

    fn gate_args() -> Vec<Argument> {
        vec![
            // double gate
            vec![
                ScalarExpression::gate_expression(5, 1, 3, 0, 7, 2),
                ScalarExpression::gate_expression(5, 2, 3, 0, 6, 2),
                ScalarExpression::gate_expression(3, 1, 1, 0, 2, 0),
            ],
            // cond_add gate
            vec![
                ScalarExpression::gate_expression(3, 2, 5, 0, 7, 2),
                ScalarExpression::gate_expression(3, 3, 5, 0, 7, 2),
                ScalarExpression::gate_expression(5, 1, 1, 0, 4, 0),
            ],
            // membership gate
            vec![ScalarExpression::gate_expression(5, 2, 3, 0, 7, 2)],
        ]
    }

    fn chip_deps() -> Vec<SupportedChips> {
        vec![SupportedChips::Native]
    }
}
