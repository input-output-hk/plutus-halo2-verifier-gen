//! ProofExtractionSteps type

use serde::{Deserialize, Serialize};

/// This type lists all potential steps of the verifier.
/// It is used to emit the right number of phases in the given language.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) enum ProofExtractionSteps {
    // (Committed) Instance evaluation steps
    CommittedInstanceEval,
    InstanceEval,
    // Advice and fixed column related steps
    AdviceCommitments,
    AdviceEval,
    FixedEval,
    // Permutation steps
    PermutationsCommitted,
    PermutationEval(char),
    PermutationCommon,
    // Lookup steps
    LookupPermuted,
    LookupCommitment,
    LookupEval,
    // Vanishing polynomial steps
    VanishingRand,
    RandomEval,
    VanishingSplit,
    // Trashcan steps
    TrashCommitment,
    TrashEval,
    // Challenges extraction
    SqueezeChallenge,
    XCoordinate,
    YCoordinate,
    Theta,
    Beta,
    Gamma,
    Trash,
}

impl ProofExtractionSteps {
    // Return the number of commitments and scalars from a PES
    pub(crate) fn step_stat(&self) -> (usize, usize) {
        match self {
            ProofExtractionSteps::AdviceCommitments => (1, 0),
            ProofExtractionSteps::AdviceEval => (0, 1),
            ProofExtractionSteps::FixedEval => (0, 1),
            ProofExtractionSteps::LookupCommitment => (1, 0),
            ProofExtractionSteps::LookupEval => (0, 5),
            ProofExtractionSteps::LookupPermuted => (2, 0),
            ProofExtractionSteps::PermutationCommon => (0, 1),
            ProofExtractionSteps::PermutationEval(_) => (0, 1),
            ProofExtractionSteps::PermutationsCommitted => (1, 0),
            ProofExtractionSteps::RandomEval => (0, 1),
            ProofExtractionSteps::TrashCommitment => (1, 0),
            ProofExtractionSteps::TrashEval => (0, 1),
            ProofExtractionSteps::VanishingRand => (1, 0),
            ProofExtractionSteps::VanishingSplit => (1, 0),
            _ => (0, 0),
        }
    }
}
