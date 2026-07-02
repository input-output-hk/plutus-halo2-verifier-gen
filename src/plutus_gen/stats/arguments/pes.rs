use super::super::data::CircuitStatistics;
use crate::plutus_gen::stats::estimate::build::Processed;

/// Absorb the vk and public (committed) inputs to the transcript.
pub(crate) fn absorb_vk_and_inputs(
    stats: &mut CircuitStatistics,
    nb_public_inputs: usize,
    nb_committed_instances: usize,
) {
    // Absorbing vk hash
    stats.common_scalar();

    // Absorbing committed instances
    (0..nb_committed_instances).for_each(|_| stats.common_g1());

    // Absorbing nb of public inputs (after converting the number to scalar)
    stats.int_to_scalar();
    stats.common_scalar();

    // Absorbing public inputs
    (0..nb_public_inputs).for_each(|_| stats.common_scalar());
}

/// Extract non-PCS commitments and evaluations from the transcript.
/// Also generates the instance evaluations from relevant elemnets.
pub(crate) fn process_pes(stats: &mut CircuitStatistics, processed: &Processed) {
    let circuit_degree = processed.circuit_degree;
    let nb_copy_constrained = processed.nb_copy_constrained;
    let nb_public_inputs = processed.nb_public_inputs;
    let nb_committed_instances = processed.nb_committed_instances;
    let nb_lookups = processed.lookup_args.len();
    let nb_trash_args = processed.trashcan_args.len();
    let nb_advice_fixed_evals = processed.nb_advice_fixed_evaluations;

    // Advice commitments
    (0..processed.nb_advice).for_each(|_| stats.read_point());

    // Theta
    stats.squeeze_challenge();

    // Lookup permutation
    (0..nb_lookups).for_each(|_| {
        stats.read_point(); // permuted_input_commitment
        stats.read_point(); // permuted_table_commitment
    });

    // Beta
    stats.squeeze_challenge();

    // Gamma
    stats.squeeze_challenge();

    // Permutation products
    (0..nb_copy_constrained.div_ceil(circuit_degree - 2)).for_each(|_| stats.read_point());

    // Lookup commitments
    (0..nb_lookups).for_each(|_| stats.read_point());

    // Trash challenge and trashcan commitments (between lookup products and vanishing random)
    // Even if we have no arguments, we still squeeze the challenge
    stats.squeeze_challenge(); // trash_challenge
    (0..nb_trash_args).for_each(|_| stats.read_point());

    // Vanishing randomness
    stats.read_point();

    // Y
    stats.squeeze_challenge();

    // Vanishing splits
    (0..circuit_degree - 1).for_each(|_| {
        stats.read_point();
        stats.decompress_point();
    });

    // X
    stats.squeeze_challenge();

    // x^{n-1} and x^n
    stats.pow_scalar();
    stats.mul_scalar();

    // If any committed instance, read their evaluation.
    if nb_committed_instances > 0 {
        stats.read_scalar();
    }

    // If any public input,
    // - compute 1 omega per pi
    // - compute lagrange poly basis of size nb_pi + 1
    // - compute instance evaluation as inner product of lagrange basis and public inputs
    if nb_public_inputs > 0 {
        (0..=nb_public_inputs).for_each(|_| stats.rotate_omega());
        stats.lagrange_polynomial_basis(nb_public_inputs + 1);
        stats.inner_product(nb_public_inputs + 1);
    } else {
        stats.int_to_scalar();
    }

    // Advice and Fixed columns evaluations (one per rotation)
    (0..nb_advice_fixed_evals).for_each(|_| stats.read_scalar());

    // Vanishing random evaluation
    stats.read_scalar();

    // Permutation evaluations
    // - Permutation common evaluations
    (0..nb_copy_constrained).for_each(|_| stats.read_scalar()); // permutation common
    // - Permutation cross-term evaluations
    (0..(3 * nb_copy_constrained.div_ceil(circuit_degree - 2) - 1))
        .for_each(|_| stats.read_scalar());

    // Lookup evaluations
    (0..nb_lookups).for_each(|_| {
        stats.read_scalar(); // product_eval
        stats.read_scalar(); // product_eval_next
        stats.read_scalar(); // permuted_input_eval
        stats.read_scalar(); // permuted_input_inv_eval
        stats.read_scalar(); // permuted_table_eval
    });

    // Trashcan evaluations
    (0..nb_trash_args).for_each(|_| stats.read_scalar());
}
