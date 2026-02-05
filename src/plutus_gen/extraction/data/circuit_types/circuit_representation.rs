//! Circuit representation and associated functions.

use super::{
    super::ProofExtractionSteps, CircuitExpressions, CircuitQueries, InstantiationSpecificData,
};

use itertools::Itertools;

use crate::plutus_gen::extraction::pcs::ExtractPCS;

/// CircuitRepresentation structure
/// This structure stores all expressions, queries and data from a given
/// circuit and associated verification key.
#[derive(Clone, Debug, Default)]
pub struct CircuitRepresentation<PCS: ExtractPCS + ?Sized> {
    pub proof_instantiation_data: InstantiationSpecificData,
    pub pcs_instantiation_data: PCS::PCSData,
    pub public_inputs: i32, // public_inputs are scalars
    pub committed_instances: usize,
    pub proof_extraction_steps: Vec<ProofExtractionSteps>,
    pub pcs_extraction_steps: Vec<PCS::PCSExtractionSteps>,
    pub expressions: CircuitExpressions,
    pub queries: CircuitQueries,
}

impl<PCS: ExtractPCS> CircuitRepresentation<PCS> {
    /// Initialize a new CircuitRepresentation with default values.
    pub fn new() -> Self {
        CircuitRepresentation {
            proof_instantiation_data: InstantiationSpecificData::default(),
            pcs_instantiation_data: PCS::PCSData::default(),
            public_inputs: 0,
            committed_instances: 0,
            proof_extraction_steps: vec![],
            pcs_extraction_steps: vec![],
            expressions: CircuitExpressions::default(),
            queries: CircuitQueries::default(),
        }
    }
}

impl<PCS: ExtractPCS> CircuitRepresentation<PCS> {
    /// Comptues the permutation sets
    pub fn compute_sets(&self) -> Vec<char> {
        self.proof_extraction_steps
            .iter()
            .filter(|e| matches!(e, ProofExtractionSteps::PermutationEval(_)))
            .chunk_by(|e| match e {
                ProofExtractionSteps::PermutationEval(code) => code,
                _ => panic!("unexpected proof extraction step"),
            })
            .into_iter()
            .map(|(c, _)| *c)
            .collect()
    }

    /// Returns the number of common permutation expressions.
    pub fn nb_permutation_common(&self) -> usize {
        self.proof_extraction_steps
            .iter()
            .filter(|e| matches!(e, ProofExtractionSteps::PermutationCommon))
            .count()
    }

    /// Returns the number of lookup commitments.
    pub fn nb_lookup_commitments(&self) -> usize {
        self.proof_extraction_steps
            .iter()
            .filter(|e| **e == ProofExtractionSteps::LookupCommitment)
            .count()
    }

    /// Returns the number of times we split the vanishing polynomial.
    pub fn nb_vanishing_splits(&self) -> usize {
        self.proof_extraction_steps
            .iter()
            .filter(|e| **e == ProofExtractionSteps::VanishingSplit)
            .count()
    }

    /// Increment the number of public inputs.
    pub fn increment_public_inputs(&mut self) {
        self.public_inputs += 1;
    }

    /// Extract the permutation evaluation step to the circuit representation.
    pub fn extract_permutation_eval(&mut self, subscript: char) -> () {
        self.proof_extraction_steps
            .push(ProofExtractionSteps::PermutationEval(subscript))
    }

    /// Extract most proof steps to the circuit representation.
    pub fn extract_step(&mut self, step: ProofExtractionSteps) -> () {
        match step {
            ProofExtractionSteps::PermutationEval(_) => panic!("Not supported"),
            ProofExtractionSteps::AdviceCommitments => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::AdviceCommitments),
            ProofExtractionSteps::SqueezeChallenge => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::SqueezeChallenge),
            ProofExtractionSteps::AdviceEval => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::AdviceEval),
            ProofExtractionSteps::FixedEval => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::FixedEval),
            ProofExtractionSteps::PermutationsCommitted => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::PermutationsCommitted),
            ProofExtractionSteps::PermutationCommon => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::PermutationCommon),
            ProofExtractionSteps::LookupPermuted => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::LookupPermuted),
            ProofExtractionSteps::LookupCommitment => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::LookupCommitment),
            ProofExtractionSteps::LookupEval => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::LookupEval),
            ProofExtractionSteps::VanishingRand => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::VanishingRand),
            ProofExtractionSteps::RandomEval => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::RandomEval),
            ProofExtractionSteps::VanishingSplit => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::VanishingSplit),
            ProofExtractionSteps::XCoordinate => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::XCoordinate),
            ProofExtractionSteps::YCoordinate => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::YCoordinate),
            ProofExtractionSteps::Theta => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::Theta),
            ProofExtractionSteps::Beta => {
                self.proof_extraction_steps.push(ProofExtractionSteps::Beta)
            }
            ProofExtractionSteps::Gamma => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::Gamma),
        }
    }
}
