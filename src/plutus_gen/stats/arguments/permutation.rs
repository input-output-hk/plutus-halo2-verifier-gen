use super::super::chips::RotationSet;
use super::super::data::CircuitStatistics;

pub(crate) const PERM_DEGREE: usize = 3;

/// Rotation sets for polynomials introduced by the permutation argument.
/// We permute on (current, next, last) for all but the last permutation commitment.
pub(crate) fn perm_poly_rotations() -> Vec<RotationSet> {
    vec![
        RotationSet::new(false, false, true, true, false),
        RotationSet::new(false, false, true, true, true),
    ]
}

/// Rotation sets for the permutation argument's queries: one `curr()` query per
/// copy-constrained column, plus one query per permutation commitment chunk.
pub(crate) fn permutation_query_rotations(
    nb_copy_constrained: usize,
    circuit_degree: usize,
) -> Vec<RotationSet> {
    let mut permutation_queries = Vec::new();
    (0..nb_copy_constrained).for_each(|_| {
        permutation_queries.push(RotationSet::curr());
    });
    let perm_rotations = perm_poly_rotations();
    (0..nb_copy_constrained.div_ceil(circuit_degree - 2))
        .enumerate()
        .for_each(|(i, _)| {
            permutation_queries.push(if i == 0 {
                perm_rotations[0]
            } else {
                perm_rotations[1]
            });
        });
    permutation_queries
}

/// Returns the number of commitments the permutation argument contributes to
/// the verification key.
pub(crate) fn nb_perm_commitments_vk(nb_copy_constrained: usize) -> usize {
    // nb_advice + instance column (if any) permutation commitments + fixed column commitments.
    // The instance column participates in permutation whenever public inputs or committed
    // instances are present (they share the same instance column slot in the constraint system).
    nb_copy_constrained
}

/// Returns the number of commitments the permutation argument contributes to
/// the proof.
pub(crate) fn nb_perm_commitments(nb_copy_constrained: usize, circuit_degree: usize) -> usize {
    // permutations_committed_{}
    nb_copy_constrained.div_ceil(circuit_degree - 2)
}
/// Returns the number of evaluations the permutation argument contributes to
/// the proof.
pub(crate) fn nb_perm_evaluations(nb_copy_constrained: usize, circuit_degree: usize) -> usize {
    // permutation common evaluations
    // permutation_common_<1-9>
    let nb_common = nb_copy_constrained;

    // permutation product evaluations
    // permutations_evaluated_<a-z>_<1-9>
    let nb_cross_terms = 3 * nb_copy_constrained.div_ceil(circuit_degree - 2) - 1;

    nb_common + nb_cross_terms
}

pub(crate) fn evaluate_permutation_terms(
    stats: &mut CircuitStatistics,
    nb_copy_constrained: usize,
    circuit_degree: usize,
) {
    let nb_permutations = nb_copy_constrained.div_ceil(circuit_degree - 2);

    // Evaluated boundary/cross-product terms
    // term1 - first set: l_0(X) * (1 - z_0(X)) = 0
    // Product(var, Sum(var, Neg(var)))
    stats.mul_scalar();
    stats.add_scalar();
    stats.neg_scalar();

    // term2 - last set: // l_last(X) * (z_l(X)^2 - z_l(X)) = 0
    // term2: Product(var, Sum(Product(v,v), Neg(v)))
    stats.mul_scalar();
    stats.mul_scalar();
    stats.add_scalar();
    stats.neg_scalar();

    // all sets but 1st: l_0(X) * (z_i(X) - z_{i-1}(\omega^(last) X)) = 0
    // cross terms (nb_permutations - 1): Product(Sum(var, Neg(var)), var)
    (0..nb_permutations - 1).for_each(|_| {
        stats.mul_scalar();
        stats.add_scalar();
        stats.neg_scalar();
    });

    // For all sets:
    // (1 - (l_last(X) + l_blind(X))) * (
    //   z_i(\omega X) \prod (p(X) + \beta s_i(X) + \gamma)
    // - z_i(X) \prod (p(X) + \delta^i \beta X + \gamma)
    // )

    // Left terms: Prod (beta * perm_common + eval + gamma)
    // - compute each monoid
    (0..nb_copy_constrained).for_each(|_| {
        stats.mul_scalar();
        stats.add_scalar();
        stats.add_scalar();
    });
    // - computing the product of all monoid and perm evaluation
    // (we have nb_permutation sets of 2 to 3 left terms times the perm. eval)
    (0..nb_copy_constrained).for_each(|_| stats.mul_scalar()); // set batching

    // Right terms: Prod (delta^i * beta * x + eval  + gamma)
    // - compute each monoid
    (0..nb_copy_constrained).for_each(|_| {
        stats.pow_scalar();
        stats.add_scalar();
        stats.add_scalar();
        stats.mul_scalar();
        stats.mul_scalar();
    });
    // - computing the product of the monoid  and perm evaluation
    // (we have nb_permutation sets of 2 to 3 right terms times the perm. eval)
    (0..nb_copy_constrained).for_each(|_| stats.mul_scalar()); // set batching

    // Combine left and right sets
    // (left_i - right_i) * (1 - (eval + sum_blinds))
    (0..nb_permutations).for_each(|_| {
        stats.mul_scalar();
        stats.sub_scalar();
        stats.sub_scalar();
        stats.add_scalar();
    });
}
