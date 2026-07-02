//! PCS (Polynomial Commitment Scheme) cost estimation abstractions.
//!
//! [`PcsEstimate`] is implemented for each supported PCS and drives two phases of the
//! verifier cost model:
//!
//! 1. **Transcript reading** — `read_transcript` accounts for the opening proof elements
//!    that are read from the proof transcript (challenges, commitments, evaluations).
//!
//! 2. **Opening computation** — `compute_opening` accounts for the scalar multiplications
//!    needed to evaluate the batched polynomial opening (powers of the batching challenges).
//!
//! Currently only [`H2MO`] (Halo2 multi-open) is supported.

pub(crate) mod h2mo;
pub(crate) use h2mo::H2MO;

use super::data::CircuitStatistics;

/// Identifies which polynomial commitment scheme is in use.
///
/// Used to branch on PCS-specific logic (e.g. proof structure, commitment counts) in places
/// where the PCS type is not yet available as a generic parameter.
#[derive(PartialEq, Eq)]
#[allow(dead_code)]
pub enum PCSType {
    /// Halo2's multi-open scheme: batches all polynomial evaluations across multiple
    /// rotation-point sets into a single KZG opening proof.
    Halo2MultiOpen,
}

/// Cost estimation interface for a Polynomial Commitment Scheme.
///
/// Implementors describe how their opening protocol contributes to the verifier's
/// operation count, without needing a fully extracted circuit representation.
pub trait PcsEstimate {
    /// Returns the [`PCSType`] tag for this implementation.
    #[allow(dead_code)]
    fn pcs_type() -> PCSType;

    /// Accounts for the transcript elements consumed during the opening proof.
    fn read_transcript(stats: &mut CircuitStatistics, nb_point_sets: usize);

    /// Accounts for the scalar multiplications needed to compute the opening.
    fn compute_opening(
        stats: &mut CircuitStatistics,
        halo2_commitment_data: &[Vec<usize>],
        max_commitments_per_set: usize,
        kzg_halo2_point_sets: &[usize],
        nb_point_sets: usize,
    );

    /// Returns the number of commitments the PCS contributes to the vk
    fn nb_commitments_vk() -> usize;

    /// Returns the number of commitments the PCS contributes to the proof
    fn nb_commitments() -> usize;

    /// Returns the number of evaluations the PCS contributes to the vk
    fn nb_evaluations(nb_point_sets: usize) -> usize;
}
