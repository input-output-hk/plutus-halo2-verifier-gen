use super::super::circuit_statistics::CircuitStatistics;

pub(crate) fn evaluate_lookup_terms(
    stats: &mut CircuitStatistics,
    nb_lookups: usize,
    nb_lookup_expression_ops: usize,
) {
    // Input and table expression folding (add + mul to compress each expression)
    (0..2 * nb_lookups).for_each(|_| {
        stats.add_scalar();
        stats.mul_scalar();
        (0..nb_lookup_expression_ops).for_each(|_| stats.mul_scalar());
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
    });
}
