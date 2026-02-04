//! Circuit representation and associated types

use super::{
    super::ProofExtractionSteps, CircuitExpressions, CircuitQueries, InstantiationSpecificData,
};

use itertools::Itertools;

use crate::plutus_gen::extraction::pcs::ExtractPCS;

/// CircuitRepresentation type
/// This type is for extracting from a proof and verification key, and storing
/// all expressions and queries and polynomial commitment scheme's data.
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

    pub fn nb_permutation_common(&self) -> usize {
        self.proof_extraction_steps
            .iter()
            .filter(|e| matches!(e, ProofExtractionSteps::PermutationCommon))
            .count()
    }

    pub fn nb_lookup_commitments(&self) -> usize {
        self.proof_extraction_steps
            .iter()
            .filter(|e| **e == ProofExtractionSteps::LookupCommitment)
            .count()
    }

    pub fn nb_vanishing_splits(&self) -> usize {
        self.proof_extraction_steps
            .iter()
            .filter(|e| **e == ProofExtractionSteps::VanishingSplit)
            .count()
    }

    pub fn increment_public_inputs(&mut self) {
        self.public_inputs += 1;
    }

    pub fn extract_permutation_eval(&mut self, subscript: char) -> () {
        self.proof_extraction_steps
            .push(ProofExtractionSteps::PermutationEval(subscript))
    }

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
