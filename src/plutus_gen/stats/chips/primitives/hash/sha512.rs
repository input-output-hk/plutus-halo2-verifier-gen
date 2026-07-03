use super::super::super::{
    Argument, Chip, Column, LookupTable, RotationSet, ScalarExpression, SupportedChips,
};

pub(crate) struct Sha512;

impl Chip for Sha512 {
    fn advice_columns() -> Vec<Column> {
        let all_rels = RotationSet::new(false, true, true, true, true, true, false);
        let rel_all_n2 = RotationSet::new(false, true, true, true, true, false, false);
        let rel_around = RotationSet::new(false, true, true, true, false, false, false);

        vec![
            Column::advice(all_rels, true),
            Column::advice(all_rels, true),
            Column::advice(rel_all_n2, true),
            Column::advice(all_rels, true),
            Column::advice(rel_around, true),
            Column::advice(all_rels, true),
            Column::advice(all_rels, false),
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
            Column::selector(),         // q_13x4_12
            Column::selector(),         // q_13_12_5_6_13_13_2
            Column::selector(),         // q_13_10_13_10_4_13_1
            Column::selector(),         // q_3_13x3_3_11_1_1_5_1
            Column::selector(),         // q_add_mod_2_64
        ]
    }

    fn gate_args() -> Vec<Argument> {
        vec![
            // Maj(A, B, C)
            vec![ScalarExpression::gate_expression(2, 1, 12, 0, 10, 9)],
            // half Ch(E, F, G)
            vec![
                ScalarExpression::gate_expression(2, 1, 11, 0, 10, 9),
                ScalarExpression::gate_expression(2, 1, 2, 0, 1, 0),
            ],
            // Σ₀(A)
            vec![ScalarExpression::gate_expression(2, 1, 30, 0, 28, 27)],
            // Σ₁(E)
            vec![ScalarExpression::gate_expression(2, 1, 30, 0, 28, 27)],
            // σ₀(W)
            vec![ScalarExpression::gate_expression(2, 1, 36, 0, 34, 33)], // one exrta mul
            // σ₁(W)
            vec![ScalarExpression::gate_expression(2, 1, 37, 0, 35, 34)],
            // 13x4-12 decomposition
            vec![ScalarExpression::gate_expression(2, 1, 5, 0, 5, 4)],
            // 13-12-5-6-13-13-2 decomposition
            vec![
                ScalarExpression::gate_expression(2, 1, 7, 0, 7, 6),
                ScalarExpression::gate_expression(2, 1, 7, 0, 7, 6),
            ],
            // 13-10-13-10-4-13-1 decomposition
            vec![
                ScalarExpression::gate_expression(2, 1, 7, 0, 7, 6),
                ScalarExpression::gate_expression(2, 1, 7, 0, 7, 6),
            ],
            // 3-13x3-3-11-1-1-5-1 decomposition
            vec![
                ScalarExpression::gate_expression(2, 1, 10, 0, 10, 9),
                ScalarExpression::gate_expression(2, 1, 1, 0, 2, 1),
                ScalarExpression::gate_expression(2, 1, 1, 0, 2, 1),
                ScalarExpression::gate_expression(2, 1, 1, 0, 2, 1),
            ],
            // add mod 2^64
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
        vec![LookupTable::register("SpreadTable13".to_string(), 3)]
    }

    fn chip_deps() -> Vec<SupportedChips> {
        vec![SupportedChips::Native]
    }
}
