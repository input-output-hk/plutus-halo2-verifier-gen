use blstrs::{G1Affine, G2Affine, Scalar};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ProofExtractionSteps {
    AdviceCommitments,
    SqueezeChallenge,
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
    pub scalar_delta: Scalar,
    pub scalar_zero: Scalar,
    pub scalar_one: Scalar,

    pub omega: Scalar,
    pub inverted_omega: Scalar,
    pub barycentric_weight: Scalar,

    pub s_g2: G2Affine,

    pub omega_rotation_count_for_instances: usize,
    pub omega_rotation_count_for_vanishing: usize,

    pub n_coefficient: u64,

    pub blinding_factors: usize,

    pub transcript_representation: Scalar,

    pub public_inputs_count: usize,

    pub w_values_count: usize,
}

// todo handle cases with custom gates that have more rotations then those 4?
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub enum RotationDescription {
    Last,
    Previous,
    #[default]
    Current,
    Next,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CommitmentData {
    pub commitment: String,
    pub point_set_index: usize,
    pub evaluations: Vec<String>,
    pub points: Vec<RotationDescription>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Query{
    pub commitment:String,
    pub evaluation:String,
    pub point: RotationDescription,
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
    pub advice_queries: Vec<Query>,
    pub fixed_queries: Vec<Query>,
    pub permutation_queries: Vec<Query>,
    pub common_queries: Vec<Query>,
    pub commitment_map: Vec<CommitmentData>,
    pub point_sets: Vec<Vec<RotationDescription>>,
    pub vanishing_queries: Vec<Query>,
    pub lookup_queries: Vec<Query>,
}
