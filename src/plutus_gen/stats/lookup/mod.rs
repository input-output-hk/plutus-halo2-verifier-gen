/// Cost estimation interface for a lookup argument.
pub(crate) mod plookup;
pub(crate) use plookup::PlookUp;

use crate::plutus_gen::stats::chips::{RotationSet, ScalarExpression};

use super::data::CircuitStatistics;

/// Identifies which Lookup Scheme is in use.
#[derive(PartialEq, Eq)]
#[allow(dead_code)]
pub enum LookupType {
    PlookUp,
}

pub trait LookupEstimate {
    /// Returns the [`LookupType`] tag for this implementation.
    #[allow(dead_code)]
    fn lookup_type() -> LookupType;

    /// Degree of the lookup argument
    fn lookup_degree() -> usize;

    /// Rotation sets for polynomials introduced by the lookup argument (one set per lookup).
    fn lookup_poly_rotations() -> Vec<RotationSet>;

    /// Accounts for the scalar multiplications needed to compute the opening.
    fn compute_argument(
        stats: &mut CircuitStatistics,
        nb_lookups: usize,
        nb_lookup_expression_ops: Vec<Vec<ScalarExpression>>,
    );

    /// Returns the number of commitments the Lookup contributes to the proof
    fn nb_commitments(nb_arguments: usize) -> usize;

    /// Returns the number of evaluations the Lookup contributes to the proof
    fn nb_evaluations(nb_arguments: usize) -> usize;
}
