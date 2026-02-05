//! ProofExtractionSteps type

use serde::{Deserialize, Serialize};

/// This type lists all potential steps of the verifier.
/// It is used to emit the right number of phases in the given language.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) enum ProofExtractionSteps {
    // Advice and fixed column related steps
    AdviceCommitments,
    AdviceEval,
    FixedEval,
    // Lookup steps
    PermutationsCommitted,
    PermutationEval(char),
    PermutationCommon,
    // Lookup steps
    LookupPermuted,
    LookupCommitment,
    LookupEval,
    // Vanishing polynoial steps
    VanishingRand,
    RandomEval,
    VanishingSplit,
    // Challenges extraction
    SqueezeChallenge,
    XCoordinate,
    YCoordinate,
    Theta,
    Beta,
    Gamma,
}
