//! Verifier cost estimation and computation for Halo2 circuits.
//!
//! - [`estimate_vk_size`] / [`estimate_proof_size`] — byte-size estimates from parameters
//! - [`estimate_verifier_code`] — operation-count estimate without a real circuit
//! - [`compute_verifier_code`]  — exact operation counts from an extracted circuit

pub(crate) mod arguments;
pub(crate) mod chips;
pub(crate) mod circuit_statistics;

pub(crate) mod compute;
pub(crate) mod estimate;
pub(crate) mod pcs;

pub use chips::{SupportedChips, lookup_chip};
pub use compute::compute_verifier_code;
pub use estimate::estimate_verifier_code;

use crate::plutus_gen::stats::pcs::{PCSType, PcsEstimate};

/// Estimates the verification key size in bytes (compressed G1 elements only).
/// Does not include the SRS or PCS parameters.
pub fn estimate_vk_size<PCS: PcsEstimate>(
    nb_public_inputs: usize,
    nb_advice: usize,
    nb_fixed: usize,
) -> usize {
    // nb_advice + instance column (if any) permutation commitments + fixed column commitments
    let nb_permutations = nb_advice + usize::from(nb_public_inputs > 0);
    let nb_commitments = nb_fixed + nb_permutations;
    10 + nb_commitments * 48
}

/// Estimates a lower bound for the proof size in bytes.
///
/// This is a lower bound because the exact number of evaluation points depends on the
/// gate structure; the minimal rotation set {prev, current, next} is assumed.
pub fn estimate_proof_size<PCS: PcsEstimate>(
    nb_public_inputs: usize,
    nb_advice: usize,
    nb_fixed: usize,
    nb_lookups: usize,
    circuit_degree: usize,
) -> usize {
    let nb_non_fixed = nb_advice + usize::from(nb_public_inputs > 0);
    let nb_permutations = nb_non_fixed.div_ceil(circuit_degree - 2);

    let nb_commitments = (nb_non_fixed - 1) // advice (last is implicit optimisation)
        + nb_permutations
        + 1 // vanishing randomness
        + 3 * nb_lookups // input permuted, table permuted, product
        + (circuit_degree - 1) // vanishing splits
        + match PCS::pcs_type() {
            PCSType::Halo2MultiOpen => 2, // f_commitment + pi_term
            PCSType::GWC19 => 3,          // w witnesses (lower bound: 3 rotation sets)
        };

    let nb_scalars = nb_non_fixed // advice evaluations (lower bound: 1 per wire)
        + nb_fixed
        + 1 // random evaluation
        + nb_non_fixed // permutation common evaluations
        + (3 * nb_permutations - 1) // perm cross-terms: Z_i(x), Z_i(x*omega), Z_{i-1}->Z_i cross (except last)
        + 5 * nb_lookups // product, product_next, input, input_inv, table
        + match PCS::pcs_type() {
            PCSType::Halo2MultiOpen => 3, // q_evals (lower bound: 3 point sets)
            PCSType::GWC19 => 0,
        };

    nb_commitments * 48 + nb_scalars * 32
}
