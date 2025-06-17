use blstrs::{G1Affine, G2Affine};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ProofExtractionSteps {
    AdviceCommitments,
    SqueezeChallange,
    AdviceEval,
    FixedEval,
    PermutationsCommited,
    PermutationEval(char),
    PermutationCommon,

    LookupPermuted,
    LookupCommitment,
    LookupEval,

    VanishingRand,
    RandomEval,
    VanishingSplit,

    Witnesses,

    XCoordinate,
    YCoordinate,

    V,
    U,

    Theta,
    Beta,
    Gamma,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct InstantiationSpecificData {
    pub fixed_commitments: Vec<G1Affine>,
    pub permutation_commitments: Vec<G1Affine>,

    // values as hex
    pub scalar_delta: String,
    pub scalar_zero: String,
    pub scalar_one: String,

    pub omega: String,
    pub inverted_omega: String,
    pub barycentric_weight: String,

    pub s_g2: G2Affine,

    pub omega_rotation_count_for_instances: usize,
    pub omega_rotation_count_for_vanishing: usize,

    pub n_coefficient: u64,

    pub blinding_factors: usize,

    pub transcript_representation: String,

    pub public_inputs_count: usize,

    pub w_values_count: usize,
}

// todo handle cases with custom gates that have more rotations then those 4?
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum RotationDescription {
    Last,
    Previous,
    Current,
    Next,
}

impl Default for RotationDescription {
    fn default() -> Self {
        RotationDescription::Current
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CircuitRepresentation {
    pub instantiation_data: InstantiationSpecificData,
    // public_inputs are scalars
    pub public_inputs: i32,
    pub proof_extraction_steps: Vec<ProofExtractionSteps>,
    pub compiled_gate_equations: Vec<String>,
    pub compiled_lookups_equations: (Vec<String>, Vec<String>),
    pub permutations_evaluated_terms: Vec<String>,
    pub permutation_terms_left: Vec<(char, String)>,
    pub permutation_terms_right: Vec<(char, String)>,
    pub h_commitments: Vec<String>,
    //query + corresponding X rotation
    pub advice_queries: Vec<(String, RotationDescription)>,
    pub fixed_queries: Vec<(String, RotationDescription)>,
    pub permutation_queries: Vec<(String, RotationDescription)>,
    pub common_queries: Vec<(String, RotationDescription)>,
    pub vanishing_queries: Vec<(String, RotationDescription)>,
    pub lookup_queries: Vec<(String, RotationDescription)>,
}
