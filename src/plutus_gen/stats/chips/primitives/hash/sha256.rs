use super::super::super::{
    Argument, Chip, Column, LookupTable, RotationSet, ScalarExpression, SupportedChips,
};

pub(crate) struct Sha256;

impl Chip for Sha256 {
    fn advice_columns() -> Vec<Column> {
        let rel_around = RotationSet::new(false, true, true, true, false, false, false);

        vec![
            Column::advice(rel_around, true),
            Column::advice(rel_around, true),
            Column::advice(rel_around, true),
            Column::advice(rel_around, true),
            Column::advice(rel_around, true),
            Column::advice(rel_around, true),
            Column::advice(rel_around, false),
            Column::advice(rel_around, false),
        ]
    }

    fn fixed_columns() -> Vec<Column> {
        vec![
            Column::shared_fixed(RotationSet::curr(), false),
            Column::shared_fixed(RotationSet::curr(), false),
        ]
    }

    fn extra_columns() -> Vec<Column> {
        vec![
            Column::complex_selector(), // q_lookup
            Column::selector(),         // q_maj
            Column::selector(),         // q_half_ch
            Column::selector(),         // q_Sigma_0
            Column::selector(),         // q_Sigma_1
            Column::selector(),         // q_sigma_0
            Column::selector(),         // q_sigma_1
            Column::selector(),         // q_11_11_10
            Column::selector(),         // q_10_9_11_2
            Column::selector(),         // q_7_12_2_5_6
            Column::selector(),         // q_12_1x3_7_3_4_3
            Column::selector(),         // q_add_mod_2_32
        ]
    }

    fn gate_args() -> Vec<Argument> {
        vec![
            // Maj(A, B, C)
            vec![ScalarExpression::gate_expression(2, 1, 8, 0, 6, 5)],
            // half Ch(E, F, G)
            vec![
                ScalarExpression::gate_expression(2, 1, 7, 0, 6, 5),
                ScalarExpression::gate_expression(2, 1, 2, 0, 1, 0),
            ],
            // Σ₀(A)
            vec![ScalarExpression::gate_expression(2, 1, 17, 0, 15, 14)],
            // Σ₁(E)
            vec![ScalarExpression::gate_expression(2, 1, 20, 0, 18, 17)],
            // σ₀(W)
            vec![ScalarExpression::gate_expression(2, 1, 28, 0, 26, 25)], // one exrta mul
            // σ₁(W)
            vec![ScalarExpression::gate_expression(2, 1, 26, 0, 24, 23)],
            // 11-11-10 decomposition
            vec![ScalarExpression::gate_expression(2, 1, 3, 0, 3, 2)],
            // 10-9-11-2 decomposition
            vec![
                ScalarExpression::gate_expression(2, 1, 4, 0, 4, 3),
                ScalarExpression::gate_expression(2, 1, 4, 0, 4, 3),
            ],
            // 7-12-2-5-6 decomposition
            vec![
                ScalarExpression::gate_expression(2, 1, 5, 0, 5, 4),
                ScalarExpression::gate_expression(2, 1, 5, 0, 5, 4),
            ],
            // 12-1x3-7-3-4-3 decomposition
            vec![
                ScalarExpression::gate_expression(2, 1, 8, 0, 8, 7),
                ScalarExpression::gate_expression(2, 1, 1, 0, 2, 1),
                ScalarExpression::gate_expression(2, 1, 1, 0, 2, 1),
                ScalarExpression::gate_expression(2, 1, 1, 0, 2, 1),
            ],
            // add mod 2^32
            vec![ScalarExpression::gate_expression(2, 1, 8, 0, 2, 1)],
        ]
    }

    fn lookup_args() -> Vec<Argument> {
        vec![
            // Lookup on nbits=fixed[0], plain = advice[0], spredd = advice[1]
            vec![
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0), // nbits
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0), // plain
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0), // sprdd
            ],
            // Lookup on nbits=fixed[1], plain = advice[2], spredd = advice[3]
            vec![
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0), // nbits
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0), // plain
                ScalarExpression::lookup_expression(2, 1, 0, 0, 0, 1, 0), // sprdd
            ],
        ]
    }

    fn lookup_tables() -> Vec<LookupTable> {
        vec![LookupTable::register("SpreadTable12".to_string(), 3)]
    }

    fn chip_deps() -> Vec<SupportedChips> {
        vec![SupportedChips::Native]
    }
}
