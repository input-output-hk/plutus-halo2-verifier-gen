use super::super::circuit_statistics::CircuitStatistics;

/// Combines all constraint expressions (gates, permutation terms, lookup terms) into the
/// vanishing polynomial via the linear combiner (y-polynomial).
pub(crate) fn combine_expressions(
    stats: &mut CircuitStatistics,
    nb_gate_equations: usize,
    nb_permutations: usize,
    nb_lookups: usize,
) {
    // Each expression costs add + mul in the linear combiner:
    //   nb_gate_equations : one per gate
    //   + 1                : vanishing polynomial identity
    //   + nb_permutations  : evaluated boundary/cross terms (term1 + term2 + nb_perm-1 cross)
    //   + nb_permutations  : one combined set per permutation chunk
    //   + 5 * nb_lookups     : l1..l5 per lookup
    let total = nb_gate_equations + 1 + 2 * nb_permutations + 5 * nb_lookups;
    (0..total).for_each(|_| {
        stats.add_scalar();
        stats.mul_scalar();
    });
}

/// Checks the vanishing polynomial: computes h(x) and verifies against committed splits.
pub(crate) fn check_vanishing(stats: &mut CircuitStatistics, circuit_degree: usize) {
    stats.sub_scalar(); // x^n - 1
    stats.inv_scalar(); // recip
    stats.mul_scalar(); // h_eval * inverted

    // h_commitments: circuit_degree - 1 entries; each is Sum(Scale(_, xn), VanishingSplit).
    // Each entry contributes 1 scale + 1 add_point.
    (0..circuit_degree - 1).for_each(|_| {
        stats.scale();
        stats.add_point();
    });
    stats.compress_point();
}
