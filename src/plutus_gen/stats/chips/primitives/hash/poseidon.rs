use super::super::super::{Argument, Chip, Column, RotationSet, ScalarExpression, SupportedChips};

/// Poseidon chip (ZkStdLib, WIDTH=3, NB_FULL_ROUNDS=8, NB_PARTIAL_ROUNDS=60, NB_SKIPS_CIRCUIT=5).
pub(crate) struct Poseidon;

impl Chip for Poseidon {
    fn advice_columns() -> Vec<Column> {
        vec![
            Column::advice(RotationSet::new(false, false, true, true, false), true),
            Column::advice(RotationSet::new(false, false, true, true, false), true),
            Column::advice(RotationSet::new(false, false, true, true, false), true),
            Column::advice(RotationSet::curr(), false),
            Column::advice(RotationSet::curr(), false),
            Column::advice(RotationSet::curr(), false),
            Column::advice(RotationSet::curr(), false),
            Column::advice(RotationSet::curr(), false),
        ]
    }

    fn fixed_columns() -> Vec<Column> {
        vec![
            Column::shared_fixed(RotationSet::curr(), false),
            Column::shared_fixed(RotationSet::curr(), false),
            Column::shared_fixed(RotationSet::curr(), false),
            Column::shared_fixed(RotationSet::curr(), false),
            Column::shared_fixed(RotationSet::curr(), false),
            Column::shared_fixed(RotationSet::curr(), false),
            Column::shared_fixed(RotationSet::curr(), false),
            Column::shared_fixed(RotationSet::curr(), false),
        ]
    }

    fn extra_columns() -> Vec<Column> {
        vec![
            Column::selector(),         // q_full_round
            Column::complex_selector(), // q_partial_round
        ]
    }

    fn gate_args() -> Vec<Argument> {
        vec![
            // full_round_gate
            vec![
                // hint checks: q_full_round * (x_i.cur^3 - x_{i+3}.cur)
                ScalarExpression::gate_expression(4, 1, 1, 0, 3, 0),
                ScalarExpression::gate_expression(4, 1, 1, 0, 3, 0),
                ScalarExpression::gate_expression(4, 1, 1, 0, 3, 0),
                // linear layer: q_full_round * (fixed_cur[i] - x_i.next[i] + MDS[i][1] * x_1.cur^2 * x_4.cur + MDS[i][2] * x_2.cur^2 * x_5.cur + MDS[i][3] * x_3.cur^2 * x_6.cur)
                ScalarExpression::gate_expression(4, 1, 4, 0, 10, 3),
                ScalarExpression::gate_expression(4, 1, 4, 0, 10, 3),
                ScalarExpression::gate_expression(4, 1, 4, 0, 10, 3),
            ],
        ]
    }

    fn trash_args() -> Vec<Argument> {
        vec![
            // partial round gate
            vec![
                // 2 LIN constraints
                ScalarExpression::trashcan_expression(5, 1, 9, 0, 32, 8),
                ScalarExpression::trashcan_expression(5, 1, 9, 0, 32, 8),
                // 6 SBOX constraints (SKIP of 5, increasing nb of variables)
                ScalarExpression::trashcan_expression(5, 1, 4, 0, 7, 3),
                ScalarExpression::trashcan_expression(5, 1, 5, 0, 12, 4),
                ScalarExpression::trashcan_expression(5, 1, 6, 0, 17, 5),
                ScalarExpression::trashcan_expression(5, 1, 7, 0, 22, 6),
                ScalarExpression::trashcan_expression(5, 1, 8, 0, 27, 7),
                ScalarExpression::trashcan_expression(5, 1, 9, 0, 32, 8),
            ],
        ]
    }

    fn chip_deps() -> Vec<SupportedChips> {
        vec![SupportedChips::Native]
    }
}
