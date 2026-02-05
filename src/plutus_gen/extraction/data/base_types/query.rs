//! Query structure and associated functions

use super::{Commitments, Evaluations, RotationDescription};
use serde::{Deserialize, Serialize};
/// This structure is used to store the relation between commitments and
/// evaluations as well as the associated rotation.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Query {
    pub commitment: Commitments,
    pub evaluation: Evaluations,
    pub point: RotationDescription,
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
