//! CommitmentData type

use super::*;

/// Type storing all information associated to a commitment
#[derive(Clone, Debug, Default)]
pub struct CommitmentData {
    pub commitment: Commitments,
    pub point_set_index: usize,
    pub evaluations: Vec<Evaluations>,
    pub points: Vec<RotationDescription>,
}
