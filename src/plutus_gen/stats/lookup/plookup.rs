use crate::plutus_gen::stats::chips::{RotationSet, ScalarExpression};
use crate::plutus_gen::stats::lookup::LookupEstimate;

use super::super::data::CircuitStatistics;
pub(crate) struct PlookUp;

impl LookupEstimate for PlookUp {
    fn lookup_type() -> super::LookupType {
        super::LookupType::PlookUp
    }

    /// The maximum degree of the lookup expression
    /// Unless stated otherwise, we assume we perform a simple lookup, i.e. q_lookup * advice = table hence a degree 2 for the input_degree (on the left) and a degree 1 for the table_degree (on the right). The degree expression is max(4, 2 + input_degree + table_degree)
    fn lookup_degree() -> usize {
        5
    }

    // - Z_lookup (product polynomial): queried at {cur, next}.
    // - A_permuted (permuted input):   queried at {prev, cur}.
    // - S_permuted (permuted table):   queried at {cur}.
    fn lookup_poly_rotations() -> Vec<RotationSet> {
        vec![
            RotationSet::new(false, false, true, true, false, false, false),
            RotationSet::new(false, true, true, false, false, false, false),
            RotationSet::curr(),
        ]
    }

    fn compute_argument(
        stats: &mut CircuitStatistics,
        nb_lookups: usize,
        lookup_expression_ops: Vec<Vec<ScalarExpression>>,
    ) {
        // Input and table expression folding (add + mul to compress each expression)
        lookup_expression_ops.iter().for_each(|lookup_arg| {
            lookup_arg.iter().for_each(|lookup_exp| {
                (0..2).for_each(|_| stats.add_scalar());
                (0..2).for_each(|_| stats.mul_scalar());

                // Input & Table expressions merged together
                stats.consume_expression(lookup_exp);
            })
        });

        // Fixed-structure lookup constraint equations
        (0..nb_lookups).for_each(|_| {
            stats.sub_scalar(); // l1: 1 - product_eval
            stats.mul_scalar();
            stats.mul_scalar(); // l2: product_eval²
            stats.sub_scalar();
            stats.mul_scalar();
            stats.add_scalar(); // lookup_left: + beta
            stats.add_scalar(); //              + gamma
            stats.mul_scalar();
            stats.mul_scalar();
            stats.add_scalar(); // lookup_right: + beta
            stats.add_scalar(); //               + gamma
            stats.mul_scalar();
            stats.mul_scalar();
            stats.sub_scalar(); // l3: left - right
            stats.mul_scalar(); //     * active_rows
            stats.sub_scalar(); // l4
            stats.mul_scalar();
            stats.sub_scalar(); // l5
            stats.mul_scalar();
            stats.sub_scalar();
            stats.mul_scalar();
        })
    }

    fn nb_commitments(nb_arguments: usize) -> usize {
        Self::lookup_poly_rotations().len() * nb_arguments
    }

    fn nb_evaluations(nb_arguments: usize) -> usize {
        let nb_evals_per_arg: usize = Self::lookup_poly_rotations()
            .iter()
            .map(|r| r.count())
            .sum();
        nb_evals_per_arg * nb_arguments
    }
}
