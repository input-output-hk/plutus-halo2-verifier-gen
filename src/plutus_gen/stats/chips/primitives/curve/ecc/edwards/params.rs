use num_bigint::BigInt;

use super::super::FieldEmulationParams;

// Only takes as input the Base field emulation parameters
pub(crate) trait EdwardsEmulationParams: FieldEmulationParams {
    // Curve parameter A (not yet consumed by the cost estimator)
    #[allow(dead_code)]
    fn a() -> BigInt;

    // Curve parameter D (not yet consumed by the cost estimator)
    #[allow(dead_code)]
    fn d() -> BigInt;
}
