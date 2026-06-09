//! Verifier cost estimation and computation for Halo2 circuits.
//!
//! - [`vk_size`] / [`proof_size`] — byte-size estimates from parameters
//! - [`verifier_stats`] — operation-count estimate without a real circuit
//! - [`compute_verifier_code`]  — exact operation counts from an extracted circuit

pub(crate) mod arguments;
pub(crate) mod chips;
pub(crate) mod data;

pub(crate) mod estimate;
pub(crate) mod lookup;
pub(crate) mod pcs;

pub use chips::types::scalar_ops::ScalarOps;
pub use chips::{SupportedChips, lookup_chip};

pub use data::CircuitConfig;
pub(crate) use data::CircuitStatistics;
pub use estimate::{proof_size, verifier_stats, vk_size};
