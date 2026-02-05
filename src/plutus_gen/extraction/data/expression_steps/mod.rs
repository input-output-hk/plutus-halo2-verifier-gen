//! Code for extracting the expressions for the proof different steps:
//! - general steps in proof.rs
//! - permutation argument in permutation.rs
//! - vanishing argument in vanishing.rs

mod permutation;
mod proof;
mod vanishing;

pub(crate) use permutation::*;
pub(crate) use proof::*;
pub(crate) use vanishing::*;
