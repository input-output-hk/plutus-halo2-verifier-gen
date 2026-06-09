use num_bigint::BigInt;

use super::super::FieldEmulationParams;

// Only takes as input the Base field emulation parameters
pub(crate) trait EccEmulationParams: FieldEmulationParams {
    // Curve parameter B
    fn b() -> BigInt;
}
