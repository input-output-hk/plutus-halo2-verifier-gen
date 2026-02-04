//! ProofExtractionSteps type and associated functions

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

    Theta,
    Beta,
    Gamma,
}
