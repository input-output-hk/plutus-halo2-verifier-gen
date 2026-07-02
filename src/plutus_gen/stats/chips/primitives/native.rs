use super::super::{Argument, Chip, Column, RotationSet, ScalarExpression};

/// Base arithmetic chip shared by all midnight-zk composite chips (NativeChip).
pub(crate) struct Native;

impl Chip for Native {
    fn advice_columns() -> Vec<Column> {
        vec![
            Column::advice(RotationSet::new(false, false, true, true, false), true),
            Column::advice(RotationSet::new(false, false, true, true, false), true),
            Column::advice(RotationSet::new(false, false, true, true, false), true),
            Column::advice(RotationSet::curr(), true),
            Column::advice(RotationSet::curr(), true),
        ]
    }

    fn fixed_columns() -> Vec<Column> {
        vec![
            Column::shared_fixed(RotationSet::curr(), false), // q_1
            Column::shared_fixed(RotationSet::curr(), false), // q_2
            Column::shared_fixed(RotationSet::curr(), false), // q_3
            Column::shared_fixed(RotationSet::curr(), false), // q_4
            Column::shared_fixed(RotationSet::curr(), false), // q_5
            Column::shared_fixed(RotationSet::curr(), false), // q_next
            Column::shared_fixed(RotationSet::curr(), false), // q_12
            Column::shared_fixed(RotationSet::curr(), false), // q_13
            Column::shared_fixed(RotationSet::curr(), false), // q_constant
        ]
    }

    fn extra_columns() -> Vec<Column> {
        vec![
            Column::exclusive_fixed(RotationSet::curr(), true), // fixed_values (exclusive, copy-constrained)
            Column::selector(),                                 // q_arith
            Column::selector(),                                 // q_12_minus_34
            Column::selector(),                                 // q_parallel
        ]
    }

    fn gate_args() -> Vec<Argument> {
        vec![
            // arith: q_arith * [qc + ∑_{1..5} q_i * w_i + q_next * w_1_next + q_12 * w_1 * w_2 + q13 * w_1 * w*3]
            vec![ScalarExpression::gate_expression(4, 0, 8, 0, 11, 0)],
            // q_12_minus_34 * [(w_1 + w_2) - (w_3 + w_4)]
            vec![ScalarExpression::gate_expression(2, 2, 3, 0, 1, 0)],
            // q_parallel * [w_i + q_i - w_i_next] for 3 wires
            vec![
                ScalarExpression::gate_expression(2, 1, 2, 0, 1, 0),
                ScalarExpression::gate_expression(2, 1, 2, 0, 1, 0),
                ScalarExpression::gate_expression(2, 1, 2, 0, 1, 0),
            ],
        ]
    }

    // NR_POW2RANGE_COLS set to 1 to follow zk_stdlib
    fn nr_pow2range() -> usize {
        1
    }
}
