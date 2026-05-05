//! Estimation of verifier operation counts from circuit parameters, without requiring
//! a fully extracted `CircuitRepresentation`.
use super::arguments::lookup::evaluate_lookup_terms;
use super::arguments::permutation::evaluate_permutation_terms;
use super::arguments::pes::{absorb_vk_and_inputs, read_pes_commitments, read_pes_evaluations};
use super::arguments::vanishing::{check_vanishing, combine_expressions};
use super::circuit_statistics::CircuitStatistics;
use super::pcs::PcsEstimate;
use super::{Arith, Chip, estimate_proof_size, estimate_vk_size};

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

/// Estimates verifier operation counts from circuit parameters alone.
///
/// All counts are lower bounds: they assume the minimal rotation set {prev, current, next}.
/// Blinding factors are derived from the maximum advice rotation depth across gates and arguments:
/// gates contribute `Arith::NB_EVAL_POINTS`, permutation 2, lookups 3.
pub fn estimate_verifier_code<PCS>(
    nb_public_inputs: usize,
    nb_advice: usize,
    nb_fixed: usize,
    nb_lookups: usize,
    circuit_degree: usize,
) -> CircuitStatistics
where
    PCS: PcsEstimate,
{
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
        Arith::NB_EVAL_POINTS,
        if nb_non_fixed > 0 { 2 } else { 0 }, // permutation: x and x·ω
        if nb_lookups > 0 { 3 } else { 0 },   // lookup: x, x·ω, x·ω⁻¹
    ]
    .into_iter()
    .max()
    .unwrap()
        + 1;
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

    Arith.update_stats(&mut stats);
    let nb_gate_equations = Arith::NB_EQUATIONS;
    evaluate_lookup_terms(&mut stats, nb_lookups, Arith::NB_LOOKUP_EXPRESSION_OPS);
    evaluate_permutation_terms(&mut stats, nb_non_fixed, nb_permutations);
    combine_expressions(&mut stats, nb_gate_equations, nb_permutations, nb_lookups);

    check_vanishing(&mut stats, circuit_degree);

    stats
}
