//! ProofExtractionSteps type and associated functions

use super::CircuitRepresentation;

use itertools::Itertools;
use serde::{Deserialize, Serialize};

/// This type lists all potential steps of the verifier.
/// It is used to emit the right number of phases in the given language
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ProofExtractionSteps {
    AdviceCommitments,
    SqueezeChallenge,
    AdviceEval,
    FixedEval,
    PermutationsCommitted,
    PermutationEval(char),
    PermutationCommon,

    LookupPermuted,
    LookupCommitment,
    LookupEval,

    VanishingRand,
    RandomEval,
    VanishingSplit,

    XCoordinate,
    YCoordinate,

    //elements related to Halo2 version of multiopen KZG
    X1,
    X2,
    X3,
    X4,
    FCommitment,
    PI,
    QEvals,
    //
    Theta,
    Beta,
    Gamma,

    // elements related to Midnight-zk library
    Trash,
}

impl CircuitRepresentation {
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
            ProofExtractionSteps::X1 => self.proof_extraction_steps.push(ProofExtractionSteps::X1),
            ProofExtractionSteps::X2 => self.proof_extraction_steps.push(ProofExtractionSteps::X2),
            ProofExtractionSteps::X3 => self.proof_extraction_steps.push(ProofExtractionSteps::X3),
            ProofExtractionSteps::X4 => self.proof_extraction_steps.push(ProofExtractionSteps::X4),
            ProofExtractionSteps::FCommitment => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::FCommitment),
            ProofExtractionSteps::PI => self.proof_extraction_steps.push(ProofExtractionSteps::PI),
            ProofExtractionSteps::QEvals => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::QEvals),
            ProofExtractionSteps::Theta => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::Theta),
            ProofExtractionSteps::Beta => {
                self.proof_extraction_steps.push(ProofExtractionSteps::Beta)
            }
            ProofExtractionSteps::Gamma => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::Gamma),
            ProofExtractionSteps::Trash => self
                .proof_extraction_steps
                .push(ProofExtractionSteps::Trash),
        }
    }
}
