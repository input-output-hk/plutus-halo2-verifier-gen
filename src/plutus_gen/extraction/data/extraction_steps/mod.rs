//! Code for extracting the expressions and steps for the proof different
//! building blocks:
//! - general steps in proof.rs
//! - permutation argument in permutation.rs
//! - vanishing argument in vanishing.rs

mod permutation;
mod proof;
mod vanishing;

pub(crate) use permutation::*;
pub(crate) use proof::*;
pub(crate) use vanishing::*;
