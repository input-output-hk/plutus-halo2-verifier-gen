use super::super::circuit_statistics::CircuitStatistics;

pub(crate) fn absorb_vk_and_inputs(stats: &mut CircuitStatistics, nb_public_inputs: usize) {
    stats.common_scalar(); // vk hash
    stats.common_scalar(); // PI count
    stats.from_int_scalar();
    (0..nb_public_inputs).for_each(|_| stats.common_scalar());
}

pub(crate) fn read_pes_commitments(
    stats: &mut CircuitStatistics,
    nb_advice: usize,
    nb_lookups: usize,
    nb_permutations: usize,
    circuit_degree: usize,
) {
    // Advice commitments
    (0..nb_advice).for_each(|_| stats.read_point());
    // Theta, then lookup permuted pairs (input + table per lookup)
    stats.squeeze_challenge();
    (0..nb_lookups).for_each(|_| {
        stats.read_point();
        stats.read_point();
    });
    // Beta, Gamma
    stats.squeeze_challenge();
    stats.squeeze_challenge();
    // Permutation products, lookup products, vanishing randomness
    (0..nb_permutations).for_each(|_| stats.read_point());
    (0..nb_lookups).for_each(|_| stats.read_point());
    stats.read_point();
    // Y, vanishing splits, X
    stats.squeeze_challenge();
    (0..circuit_degree - 1).for_each(|_| stats.read_point());
    stats.squeeze_challenge();
}

pub(crate) fn read_pes_evaluations(
    stats: &mut CircuitStatistics,
    nb_non_fixed: usize,
    nb_fixed: usize,
    nb_permutations: usize,
    nb_lookups: usize,
) {
    (0..nb_non_fixed).for_each(|_| stats.read_scalar()); // advice
    (0..nb_fixed).for_each(|_| stats.read_scalar()); // fixed
    stats.read_scalar(); // random
    (0..nb_non_fixed).for_each(|_| stats.read_scalar()); // permutation common
    // Each set: eval + eval_next + cross_eval, except last set has no cross
    (0..3 * nb_permutations - 1).for_each(|_| stats.read_scalar());
    (0..nb_lookups).for_each(|_| {
        stats.read_scalar(); // product_eval
        stats.read_scalar(); // product_eval_next
        stats.read_scalar(); // permuted_input_eval
        stats.read_scalar(); // permuted_input_inv_eval
        stats.read_scalar(); // permuted_table_eval
    });
}
