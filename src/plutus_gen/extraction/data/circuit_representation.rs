//! Circuit representation and associated types

use super::{
    CircuitExpressions, CircuitQueries, CommitmentData, InstantiationSpecificData,
    ProofExtractionSteps, Query, RotationDescription,
};

/// CircuitRepresentation type
/// This type is for extracting from a proof and verification key, and storing
/// all expressions and queries and polynomial commitment scheme's data.
#[derive(Clone, Debug, Default)]
pub struct CircuitRepresentation {
    pub instantiation_data: InstantiationSpecificData,
    // public_inputs are scalars
    pub public_inputs: i32,
    pub committed_instances: usize,
    pub proof_extraction_steps: Vec<ProofExtractionSteps>,
    pub expressions: CircuitExpressions,
    pub queries: CircuitQueries,
    pub kzg: CircuitKZG,
}

/// CircuitKZG type
/// This type contains all structures and value needed to check KZG Polynomial
/// Commmitment Scheme .
#[derive(Clone, Debug, Default)]
pub struct CircuitKZG {
    pub commitment_map: Vec<CommitmentData>,
    pub point_sets: Vec<Vec<RotationDescription>>,
}

impl CircuitQueries {
    // Order of queries from halo2:
    // 1. INSTANCE
    // 2.ADVICE
    // 3. PERMUTATION
    // 4. LOOKUP
    // 5. FIXED
    // 6. COMMON
    // 7. VANISHING
    // 8. TRASHCANS
    pub fn all_ordered(&self) -> [Vec<Query>; 8] {
        [
            self.instance.clone(),
            self.advice.clone(),
            self.permutation.clone(),
            self.lookup.clone(),
            self.fixed.clone(),
            self.common.clone(),
            self.vanishing.clone(),
            self.trashcan.clone(),
        ]
    }
}
