use super::super::arguments::permutation::evaluate_permutation_terms;
use super::super::arguments::pes::{absorb_vk_and_inputs, process_pes};
use super::super::arguments::trashcans::compute_trashcans;
use super::super::arguments::vanishing::compute_vanishing;
use super::super::data::CircuitStatistics;
use super::super::lookup::{LookupEstimate, PlookUp};
use super::super::pcs::PcsEstimate;
use crate::plutus_gen::stats::chips::ScalarExpression;
use crate::plutus_gen::stats::estimate::build::Processed;
use crate::plutus_gen::stats::estimate::{estimate_proof_size, estimate_vk_size};
use log::info;

/// Returns the number of blinding factors needed for the circuit.
///
/// - `max_advice_queries` is the maximum number of rotations an advice column is queried on.
/// - `nb_trashcans` is the number of trashcan arguments.
pub(super) fn blinding_factors(max_advice_queries: usize, nb_trashcans: usize) -> usize {
    let factors = 2 + nb_trashcans + std::cmp::max(3, max_advice_queries);
    if factors > i32::MAX as usize {
        panic!("Number of blinding factors overflowed max expected value");
    }
    factors
}

/// Estimates verifier operation counts from chip descriptions and optional extra column counts.
///
/// `extra.nb_advice`, `extra.nb_fixed + extra.nb_selectors`, and `extra.nb_lookups` are summed
/// with chip-derived values. `circuit_degree` is the max of `extra.degree` and the chips'
/// degrees. All counts are lower bounds: they assume the minimal rotation set {prev, cur, next}.
pub fn estimate_verifier_code<PCS>(processed: Processed) -> CircuitStatistics
where
    PCS: PcsEstimate,
{
    if processed.nb_advice == 0 {
        return CircuitStatistics::default();
    }

    let nb_gates = processed.gate_args.len();
    info!("nb_gates {nb_gates}");

    let nb_lookups = processed.lookup_args.len();
    info!("nb_lookups {nb_lookups}");

    let nb_trashcans = processed.trashcan_args.len();
    info!("nb_trashcans {nb_trashcans}");

    let size_proof = estimate_proof_size::<PCS>(
        processed.nb_committed_instances,
        processed.nb_advice,
        nb_lookups,
        nb_trashcans,
        processed.circuit_degree,
        processed.nb_copy_constrained,
        processed.nb_advice_fixed_evaluations,
        processed.nb_point_sets,
    )
    .bytes;

    let vk_size = estimate_vk_size::<PCS>(processed.nb_copy_constrained, processed.nb_fixed).bytes;

    // Initializing CircuitStatistics with the estimated proof size, VK size, and number of public inputs.
    let mut stats = CircuitStatistics::new(
        size_proof,
        vk_size,
        processed.circuit_degree,
        processed.nb_public_inputs,
        processed.nb_committed_instances,
    );

    // Converting constants 0, 1 and δ to scalars
    (0..3).for_each(|_| stats.int_to_scalar());

    absorb_vk_and_inputs(
        &mut stats,
        processed.nb_public_inputs,
        processed.nb_committed_instances,
    );

    // Proof Extraction Steps and input evaluation generations
    process_pes(&mut stats, &processed);
    // Polynomial Commitment Extraction Steps
    PCS::read_transcript(&mut stats, processed.nb_point_sets);

    let expected_transcript_size = 32 // absorbing hash of vk
    + 48 * processed.nb_committed_instances // absorbing committed inputs
    + 32 // absorbing nb of public inputs
    + 32 * processed.nb_public_inputs // absorbing public inputs
    + size_proof; // aborsbing proof
    assert_eq!(stats.transcript_size, expected_transcript_size);

    // Computting X rotations
    (0..processed.nb_point_sets).for_each(|_| stats.rotate_omega());

    // Computing nb of blinding factors
    let nb_blinding_factors = blinding_factors(processed.max_advice_queries, nb_trashcans);
    info!("nb_blinding_factors {nb_blinding_factors}");

    // Computing rotations for vanishing polynomial
    (0..nb_blinding_factors + 2).for_each(|_| stats.rotate_omega());

    // Computing evaluations for Lagrange polynomial
    stats.lagrange_polynomial_basis(nb_blinding_factors + 2);

    // Summing Lagrange polynomial evaluations
    (0..=nb_blinding_factors).for_each(|_| stats.add_scalar());

    // Computing active row
    stats.add_scalar();
    stats.sub_scalar();

    // Computing operations per gate
    let nb_gate_expressions: usize = processed.gate_args.iter().map(|arg| arg.len()).sum();
    info!("nb_gate_expressions {nb_gate_expressions}");
    processed.gate_args.into_iter().for_each(|arg| {
        let batched_arg = ScalarExpression::batch_expressions(arg);
        stats.consume_expression(&batched_arg);
    });

    // Computing Lookup evals
    let nb_lookup_expressions = processed
        .lookup_args
        .iter()
        .map(|arg| arg.len())
        .sum::<usize>();
    info!("nb_lookup_expressions {nb_lookup_expressions}");
    PlookUp::compute_argument(&mut stats, nb_lookups, processed.lookup_args);

    // Computing Permutation evals
    let nb_permutations = processed
        .nb_copy_constrained
        .div_ceil(processed.circuit_degree - 2);
    info!("nb_permutations {nb_permutations}");
    evaluate_permutation_terms(
        &mut stats,
        processed.nb_copy_constrained,
        processed.circuit_degree,
    );

    // Computing trashcans evals
    let nb_trashcan_expressions: usize = processed.trashcan_args.iter().map(|arg| arg.len()).sum();
    info!("nb_trashcan_expressions {nb_trashcan_expressions}");
    compute_trashcans(&mut stats, processed.trashcan_args);

    // Compute vanishing commitment
    compute_vanishing(
        &mut stats,
        nb_gates,
        nb_permutations,
        nb_lookups,
        nb_trashcans,
        processed.circuit_degree,
    );

    PCS::compute_opening(
        &mut stats,
        &processed.commitment_map,
        processed.max_commitments_per_query,
        &processed.kzg_halo2_point_sets,
        processed.nb_point_sets,
    );

    // If we do recursion
    if processed.recursion {
        // Compute variable accumulator left point from public inputs
        (0..2).for_each(|_| {
            // For both coordinates of the point, we reconstruct the coordinate
            // The WeierstrassBls12381::NB_LIMBS limbs are packed into 2 chunks
            (0..2).for_each(|_| {
                stats.add_scalar();
                stats.mul_scalar();
            });
        });
        stats.g1_from_coords();
        stats.scale();

        // Compute variable accumulator right point from public inputs
        // Compute variable accumulator left point from public inputs
        (0..2).for_each(|_| {
            // For both coordinates of the point, we reconstruct the coordinate
            // The WeierstrassBls12381::NB_LIMBS limbs are packed into 2 chunks
            (0..2).for_each(|_| {
                stats.add_scalar();
                stats.mul_scalar();
            });
        });
        stats.g1_from_coords();
        stats.scale();

        // Compute fixed accumulator from vk and -g1
        stats.msm(vk_size + 1);
        (0..vk_size + 1).for_each(|_| {
            stats.decompress_point();
        });

        // Combine fixed and variable accumulators (only on the right)
        stats.add_point();

        // Compute batching coefficient to batch accumulator check with proof check
        (0..4).for_each(|_| stats.compress_point());
        stats.hash_bytes(4 * 48);
        // bytes to int
        stats.int_to_scalar();

        // Batch left and right accumulators with proof before Miller Loop
        (0..2).for_each(|_| {
            stats.scale();
            stats.add_point();
        });
    }

    stats
}
