use super::super::chips::RotationSet;
use super::super::data::CircuitStatistics;

/// Rotation sets for the vanishing argument's queries: one `curr()` query each for
/// `vanishing_g` and `vanishing_rand`.
pub(crate) fn vanishing_query_rotations() -> Vec<RotationSet> {
    vec![RotationSet::curr(), RotationSet::curr()]
}

/// Returns the number of commitments the vanishing argument contributes to
/// the proof.
pub(crate) fn nb_vanish_commitments(circuit_degree: usize) -> usize {
    let nb_random = 1;

    let nb_splits = circuit_degree - 1;

    nb_random + nb_splits
}

/// Returns the number of evaluations the vanishing argument contributes to
/// the proof.
pub(crate) fn nb_vanish_evaluations() -> usize {
    1
}

/// Combines all constraint expressions (gates, permutation terms, lookup terms, trash terms)
/// into the vanishing polynomial via the linear combiner (y-polynomial).
/// Batch this polynomial with the splits vanishing commitments.
pub(crate) fn compute_vanishing(
    stats: &mut CircuitStatistics,
    nb_gate_equations: usize,
    nb_permutations: usize,
    nb_lookups: usize,
    nb_trash_args: usize,
    circuit_degree: usize,
) {
    // Each expression costs add + mul in the linear combiner:
    //   nb_gate_equations : one per gate
    //   + 2 + nb_permutations -1  : evaluated boundary/cross terms (term1 + term2 + nb_perm-1 cross)
    //   + nb_permutations  : one combined set per permutation chunk
    //   + 5 * nb_lookups   : l1..l5 per lookup
    //   + nb_trash_args    : one compressed check expression per trash argument
    let total = nb_gate_equations + 1 + 2 * nb_permutations + 5 * nb_lookups + nb_trash_args;
    (0..total).for_each(|_| {
        stats.add_scalar();
        stats.mul_scalar();
    });

    // vanishing * 1/(x^n - 1) with x^n already computed
    stats.sub_scalar();
    stats.inv_scalar();
    stats.mul_scalar();

    // h_commitments: circuit_degree - 1 entries; each is Sum(Scale(_, xn), VanishingSplit).
    // Each entry contributes 1 scale + 1 add_point.
    (0..circuit_degree - 1).for_each(|_| {
        stats.scale();
        stats.add_point();
    });
    stats.compress_point();
}
