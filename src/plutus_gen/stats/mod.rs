//! Verifier cost estimation and computation for Halo2 circuits.
//!
//! - [`vk_size`] / [`proof_size`] — byte-size estimates from parameters
//! - [`verifier_stats`] — operation-count estimate without a real circuit
//! - [`compute_verifier_code`]  — exact operation counts from an extracted circuit

pub(crate) mod arguments;
pub(crate) mod chips;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod cli;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod compute;
pub(crate) mod data;
pub(crate) mod estimate;
pub(crate) mod lookup;
pub(crate) mod pcs;
pub(crate) mod profile;

pub use chips::types::scalar_ops::ScalarOps;
pub use chips::{SupportedChips, lookup_chip};
#[cfg(not(target_arch = "wasm32"))]
pub use cli::EstimateCliArguments;
#[cfg(not(target_arch = "wasm32"))]
pub use compute::compute_verifier_code;
pub use data::CircuitConfig;
pub(crate) use data::CircuitStatistics;

pub use estimate::{AllEstimates, all_estimates, proof_size, verifier_stats, vk_size};

pub use profile::{ChipProfile, chip_profile};
