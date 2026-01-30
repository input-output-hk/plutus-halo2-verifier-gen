//! RotationDescription type and associated functions

// TODO handle cases with custom gates that have more rotations then those 4?

/// RotationDescription handles only rotations with value -1, 0, and 1.
/// This is done to reduce the number of scalars to use on the plutus side.
/// If custom rotations are implemented, check query collisions described in
/// <https://blog.zksecurity.xyz/posts/halo2-query-collision/>,
/// especially handle the case where rotation 2^k is used to check for
/// wrapping of the trace table rows
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub enum RotationDescription {
    Last,
    Previous,
    #[default]
    Current,
    Next,
}

impl RotationDescription {
    // Common functions to all languages
    pub(crate) fn to_string(&self) -> String {
        match self {
            RotationDescription::Last => "x_last".to_string(),
            RotationDescription::Previous => "x_prev".to_string(),
            RotationDescription::Current => "x_current".to_string(),
            RotationDescription::Next => "x_next".to_string(),
        }
    }

    pub(crate) fn from_i32(input: i32) -> RotationDescription {
        match input {
            -1 => RotationDescription::Previous,
            0 => RotationDescription::Current,
            1 => RotationDescription::Next,
            _ => panic!(
                "unknown number {} for rotation, only -1 0 and 1 are supported",
                input
            ),
        }
    }
}
