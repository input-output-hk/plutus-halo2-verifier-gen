//! RotationDescription type and associated functions

use serde::{Deserialize, Serialize};
use std::fmt;

// TODO handle cases with custom gates that have more rotations then those 4?

/// RotationDescription handles only rotations with value -1, 0, and 1.
/// This is done to reduce the number of scalars to use on the plutus side.
/// If custom rotations are implemented, check query collisions described in
/// <https://blog.zksecurity.xyz/posts/halo2-query-collision/>,
/// especially handle the case where rotation 2^k is used to check for
/// wrapping of the trace table rows
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Default, Hash, Serialize, Deserialize, PartialOrd, Ord,
)]
pub enum RotationDescription {
    Last,
    Previous,
    #[default]
    Current,
    Next,
    Custom(i32),
}

impl fmt::Display for RotationDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RotationDescription::Last => write!(f, "x_last"),
            RotationDescription::Previous => write!(f, "x_prev"),
            RotationDescription::Current => write!(f, "x_current"),
            RotationDescription::Next => write!(f, "x_next"),
            RotationDescription::Custom(n) => write!(f, "x_rot_{}", n),
        }
    }
}

impl RotationDescription {
    pub(crate) fn from_i32(input: i32) -> RotationDescription {
        match input {
            -1 => RotationDescription::Previous,
            0 => RotationDescription::Current,
            1 => RotationDescription::Next,
            n => RotationDescription::Custom(n),
        }
    }
}
