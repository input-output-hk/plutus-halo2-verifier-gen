//! Estimation of verifier operation counts from circuit parameters, without requiring
//! a fully extracted `CircuitRepresentation`.
use super::arguments::lookup::evaluate_lookup_terms;
use super::arguments::permutation::{PERM_NB_EVAL_POINTS, evaluate_permutation_terms};
use super::arguments::pes::{absorb_vk_and_inputs, read_pes_commitments, read_pes_evaluations};
use super::arguments::vanishing::{check_vanishing, combine_expressions};
use super::circuit_statistics::CircuitStatistics;
use super::pcs::PcsEstimate;
use super::{SupportedChips, estimate_proof_size, estimate_vk_size};
use std::cmp::max;

// --- Scalar / polynomial evaluation helpers ---

fn compute_evaluation_point(
    stats: &mut CircuitStatistics,
    blinding_factors: usize,
    nb_public_inputs: usize,
) {
    // Rotations for the vanishing polynomial range
    (0..=blinding_factors).for_each(|_| stats.rotate_omega());

    // x^n and the four key rotation points
    stats.pow_scalar();

    stats.rotate_omega(); // x_prev
    stats.rotate_omega(); // x_current
    stats.rotate_omega(); // x_next
    stats.rotate_omega(); // x_last

    // Lagrange basis for blinding factors + active_rows scalar
    stats.lagrange_polynomial_basis(1 + blinding_factors);
    (1..=blinding_factors).for_each(|_| stats.add_scalar());
    stats.add_scalar(); // add(last_eval, sum)
    stats.sub_scalar(); // sub(1, ...)

    // Lagrange basis and inner product for public inputs
    (0..nb_public_inputs).for_each(|_| stats.rotate_omega());
    stats.lagrange_polynomial_basis(nb_public_inputs);
    stats.inner_product(nb_public_inputs);
}

// --- Public entry point ---

/// Estimates verifier operation counts from chip descriptions and optional extra column counts.
///
/// `nb_advice`, `nb_fixed`, and `nb_lookups` are summed with the chip-derived values.
/// `circuit_degree` is the max of the provided value and the chips' degrees.
/// All counts are lower bounds: they assume the minimal rotation set {prev, current, next}.
pub fn estimate_verifier_code<PCS>(
    nb_public_inputs: usize,
    extra_nb_advice: usize,
    extra_nb_fixed: usize,
    extra_nb_lookups: usize,
    circuit_degree: usize,
    used_chips: &[SupportedChips],
) -> CircuitStatistics
where
    PCS: PcsEstimate,
{
    let nb_advice = extra_nb_advice + used_chips.iter().map(|c| c.nb_advice()).max().unwrap_or(0);
    let nb_fixed = extra_nb_fixed + used_chips.iter().map(|c| c.nb_fixed()).max().unwrap_or(0);
    let circuit_degree = max(
        circuit_degree,
        used_chips.iter().map(|c| c.nb_degree()).max().unwrap_or(0),
    );
    let nb_lookups = extra_nb_lookups
        + used_chips
            .iter()
            .flat_map(|c| c.lookup_tables())
            .map(|t| t.nb_columns)
            .sum::<usize>();

    let size_proof = estimate_proof_size::<PCS>(
        nb_public_inputs,
        nb_advice,
        nb_fixed,
        nb_lookups,
        circuit_degree,
    );
    let vk_size = estimate_vk_size::<PCS>(nb_public_inputs, nb_advice, nb_fixed);
    let mut stats = CircuitStatistics::new(size_proof, vk_size, nb_public_inputs);

    let nb_non_fixed = nb_advice + usize::from(nb_public_inputs > 0);
    let blinding_factors = [
        PERM_NB_EVAL_POINTS,
        if nb_non_fixed > 0 { 2 } else { 0 }, // permutation: x and x·ω
        if nb_lookups > 0 { 3 } else { 0 },   // lookup: x, x·ω, x·ω⁻¹
        used_chips
            .iter()
            .map(|chip| chip.nb_eval_points())
            .max()
            .unwrap_or(0),
    ]
    .into_iter()
    .max()
    .unwrap()
        + 2; // +1 for multiopen x3, +1 matching halo2's off-by-one defense
    let nb_permutations = nb_non_fixed.div_ceil(circuit_degree - 2);

    absorb_vk_and_inputs(&mut stats, nb_public_inputs);
    read_pes_commitments(
        &mut stats,
        nb_advice,
        nb_lookups,
        nb_permutations,
        circuit_degree,
    );
    read_pes_evaluations(
        &mut stats,
        nb_non_fixed,
        nb_fixed,
        nb_permutations,
        nb_lookups,
    );

    PCS::read_transcript(&mut stats);
    // For the minimal rotation set, the largest point set is "current" (x):
    // advice + fixed + permutations + 3×lookups (at x) + random poly + vanishing splits
    let max_commitments_per_set =
        nb_advice + nb_fixed + nb_permutations + 3 * nb_lookups + circuit_degree;
    PCS::compute_opening(
        &mut stats,
        nb_advice,
        nb_fixed,
        nb_permutations,
        nb_lookups,
        max_commitments_per_set,
    );

    compute_evaluation_point(&mut stats, blinding_factors, nb_public_inputs);

    used_chips.iter().for_each(|c| c.update_stats(&mut stats));
    let nb_gate_equations: usize = used_chips.iter().map(|c| c.nb_equations()).sum();
    let nb_lookup_expression_ops = used_chips
        .iter()
        .map(|c| c.nb_lookup_expression_ops())
        .max()
        .unwrap_or(0);
    evaluate_lookup_terms(&mut stats, nb_lookups, nb_lookup_expression_ops);
    evaluate_permutation_terms(&mut stats, nb_non_fixed, nb_permutations);
    combine_expressions(&mut stats, nb_gate_equations, nb_permutations, nb_lookups);

    check_vanishing(&mut stats, circuit_degree);

    stats
}
