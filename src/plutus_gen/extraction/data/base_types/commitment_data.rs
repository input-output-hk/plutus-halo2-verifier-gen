//! CommitmentData type

use super::*;

/// Type storing all information associated to a commitment
#[derive(Clone, Debug, Default)]
pub struct CommitmentData {
    pub(crate) commitment: Commitments,
    pub(crate) point_set_index: usize,
    pub(crate) evaluations: Vec<Evaluations>,
    pub(crate) points: Vec<RotationDescription>,
}
