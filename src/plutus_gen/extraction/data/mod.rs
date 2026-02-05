//! Data structures used for the extraction of the proof verification steps
//! from a Halo2 circuit.
//! This includes the base types, such as commitments and evaluations, as well
//! as the circuit (representation) types, built on top of the base types. It
//! also includes the expressions of Plonk's steps, that is challenges and
//! commitment extraction, as well as permutation, and vanishing, arguments,
//! and the supported languages for code emission.

// Base types, such as commitments and evaluations.
pub(crate) mod base_types;
pub(crate) use base_types::*;

// Circuit (representation) types, built on top of the base types.
pub(crate) mod circuit_types;
pub use circuit_types::CircuitRepresentation;

// Naming constants used across the codebase
pub(crate) mod constants;

// Expressions of Plonk's steps, that is challenges and commitment extraction,
// as well as permutation, and vanishing, arguments.
pub(crate) mod expression_steps;

// Supported languages
pub(crate) mod languages;
