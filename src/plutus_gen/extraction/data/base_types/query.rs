//! Query structure and associated functions

use super::{Commitments, Evaluations, RotationDescription};
use serde::{Deserialize, Serialize};
/// This structure is used to store the relation between commitments and
/// evaluations as well as the associated rotation.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Query {
    pub(crate) commitment: Commitments,
    pub(crate) evaluation: Evaluations,
    pub(crate) point: RotationDescription,
}

impl Query {
    pub(crate) fn new(
        commitment: Commitments,
        evaluation: Evaluations,
        point: RotationDescription,
    ) -> Query {
        Query {
            commitment,
            evaluation,
            point,
        }
    }
}
