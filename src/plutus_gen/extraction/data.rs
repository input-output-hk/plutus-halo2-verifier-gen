use crate::plutus_gen::extraction::data::ProofDescription::Advice;
use blstrs::{G1Affine, G2Affine, Scalar};
use halo2_proofs::plonk::Expression;
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

    XCoordinate,
    YCoordinate,

    // elements specific to GWC19 version of multiopen KZG
    V,
    U,
    Witnesses,

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

    pub q_evaluations_count: usize,
}

// todo handle cases with custom gates that have more rotations then those 4?

/// RotationDescription handles only rotations with value -1 0 and 1
/// this is done to reduce number of scalars that have to be on the plutus side
/// if allowing custom rotations is implemented remember about halo2 query collision described here
/// https://blog.zksecurity.xyz/posts/halo2-query-collision/
/// especially handle case where rotation 2^k is used to check for wrapping of the trace table rows
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default, Hash)]
pub enum RotationDescription {
    Last,
    Previous,
    #[default]
    Current,
    Next,
}

pub trait PlinthTranslator {
    fn translate_commitment(&self) -> String;
    fn translate_evaluation(&self) -> String;
}
pub trait AikenTranslator {
    fn translate_commitment(&self) -> String;
    fn translate_evaluation(&self) -> String;
}

impl PlinthTranslator for ProofDescription {
    fn translate_commitment(&self) -> String {
        match self {
            Advice(index) => {
                format!("a{:?}", index)
            }
            ProofDescription::Fixed(index) => {
                format!("f{:?}_commitment", index)
            }
            ProofDescription::Permutation(set, _) => {
                format!("permutations_committed_{}", set)
            }
            ProofDescription::Lookup(index) => {
                format!("lookupCommitment{:?}", index)
            }
            ProofDescription::PermutedInput(index) => {
                format!("permutedInput{:?}", index)
            }
            ProofDescription::PermutedTable(index) => {
                format!("permutedTable{:?}", index)
            }
            ProofDescription::PermutationsCommon(index) => {
                format!("p{:?}_commitment", index)
            }
            ProofDescription::VanishingG => "vanishing_g".to_string(),
            ProofDescription::VanishingS => panic!("VanishingS is not a commitment"),
            ProofDescription::VanishingRand => "vanishingRand".to_string(),
            ProofDescription::VanishingEval => panic!("VanishingEval is not a commitment"),
        }
    }

    fn translate_evaluation(&self) -> String {
        match self {
            Advice(index) => {
                format!("adviceEval{:?}", index)
            }
            ProofDescription::Fixed(index) => {
                format!("fixedEval{:?}", index)
            }
            ProofDescription::Permutation(set, index) => {
                format!("permutations_evaluated_{}_{}", set, index)
            }
            ProofDescription::Lookup(index) => {
                format!("product_eval_{:?}", index)
            }
            ProofDescription::PermutedInput(index) => {
                format!("permuted_input_inv_eval_{:?}", index)
            }
            ProofDescription::PermutedTable(index) => {
                format!("permuted_table_eval_{:?}", index)
            }
            ProofDescription::PermutationsCommon(index) => {
                format!("permutationCommon{:?}", index)
            }
            ProofDescription::VanishingG => panic!("VanishingG is not an evaluation"),
            ProofDescription::VanishingS => "vanishing_s".to_string(),
            ProofDescription::VanishingRand => panic!("VanishingRand is not an evaluation"),
            ProofDescription::VanishingEval => "randomEval".to_string(),
        }
    }
}

impl AikenTranslator for ProofDescription {
    fn translate_commitment(&self) -> String {
        match self {
            Advice(index) => {
                format!("a{:?}", index)
            }
            ProofDescription::Fixed(index) => {
                format!("f{:?}_commitment", index)
            }
            ProofDescription::Permutation(set, _) => {
                format!("permutations_committed_{}", set)
            }
            ProofDescription::Lookup(index) => {
                format!("lookup_commitment_{:?}", index)
            }
            ProofDescription::PermutedInput(index) => {
                format!("permuted_input_{:?}", index)
            }
            ProofDescription::PermutedTable(index) => {
                format!("permuted_table_{:?}", index)
            }
            ProofDescription::PermutationsCommon(index) => {
                format!("p{:?}_commitment", index)
            }
            ProofDescription::VanishingG => "vanishing_g".to_string(),
            ProofDescription::VanishingS => panic!("VanishingS is not a commitment"),
            ProofDescription::VanishingRand => "vanishing_rand".to_string(),
            ProofDescription::VanishingEval => panic!("VanishingEval is not a commitment"),
        }
    }

    fn translate_evaluation(&self) -> String {
        match self {
            Advice(index) => {
                format!("advice_eval_{:?}", index)
            }
            ProofDescription::Fixed(index) => {
                format!("fixed_eval_{:?}", index)
            }
            ProofDescription::Permutation(set, index) => {
                format!("permutations_evaluated_{}_{}", set, index)
            }
            ProofDescription::Lookup(index) => {
                format!("product_eval_{:?}", index)
            }
            ProofDescription::PermutedInput(index) => {
                format!("permuted_input_inv_eval_{:?}", index)
            }
            ProofDescription::PermutedTable(index) => {
                format!("permuted_table_eval_{:?}", index)
            }
            ProofDescription::PermutationsCommon(index) => {
                format!("permutation_common_{:?}", index)
            }
            ProofDescription::VanishingG => panic!("VanishingG is not an evaluation"),
            ProofDescription::VanishingS => "vanishing_s".to_string(),
            ProofDescription::VanishingRand => panic!("VanishingRand is not an evaluation"),
            ProofDescription::VanishingEval => "random_eval".to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum ProofDescription {
    Advice(usize),
    Fixed(usize),
    Permutation(char, usize),
    Lookup(usize),
    PermutedInput(usize),
    PermutedTable(usize),
    PermutationsCommon(usize),
    VanishingG,
    VanishingS,
    VanishingRand,
    VanishingEval,
}

impl Default for ProofDescription {
    fn default() -> Self {
        Advice(0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CommitmentData {
    pub commitment: ProofDescription,
    pub point_set_index: usize,
    pub evaluations: Vec<ProofDescription>,
    pub points: Vec<RotationDescription>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Query {
    pub commitment: ProofDescription,
    pub evaluation: ProofDescription,
    pub point: RotationDescription,
}

// simple DSL for verifier side equations that are not part of the prover
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ScalarExpression<F> {
    Constant(F),
    Variable(String),
    Advice(usize),
    Fixed(usize),
    Instance(usize),
    PermutationCommon(usize),
    Negated(Box<ScalarExpression<F>>),
    Sum(Box<ScalarExpression<F>>, Box<ScalarExpression<F>>),
    Product(Box<ScalarExpression<F>>, Box<ScalarExpression<F>>),
    PowMod(Box<ScalarExpression<F>>, usize),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ExpressionG1<F> {
    Zero,
    Sum(Box<ExpressionG1<F>>, Box<ExpressionG1<F>>),
    Scale(Box<ExpressionG1<F>>, ScalarExpression<F>),
    VanishingSplit(usize),
    Variable(String),
}

#[derive(Clone, Debug, Default)]
pub struct CircuitRepresentation {
    pub instantiation_data: InstantiationSpecificData,
    // public_inputs are scalars
    pub public_inputs: i32,
    pub proof_extraction_steps: Vec<ProofExtractionSteps>,
    pub compiled_gate_equations: Vec<Expression<Scalar>>,
    pub compiled_lookups_equations: (Vec<Vec<Expression<Scalar>>>, Vec<Vec<Expression<Scalar>>>),
    pub permutations_evaluated_terms: Vec<ScalarExpression<Scalar>>,
    pub permutation_terms_left: Vec<(char, ScalarExpression<Scalar>)>,
    pub permutation_terms_right: Vec<(char, ScalarExpression<Scalar>)>,
    pub h_commitments: Vec<(String, ExpressionG1<Scalar>)>,
    //query + corresponding X rotation
    pub advice_queries: Vec<Query>,
    pub fixed_queries: Vec<Query>,
    pub permutation_queries: Vec<Query>,
    pub common_queries: Vec<Query>,
    pub vanishing_queries: Vec<Query>,
    pub lookup_queries: Vec<Query>,
    pub commitment_map: Vec<CommitmentData>,
    pub point_sets: Vec<Vec<RotationDescription>>,
}

impl CircuitRepresentation {
    // order of queries from halo2:
    // ADVICE
    // PERMUTATION
    // LOOKUP
    // FIXED
    // COMMON
    // VANISHING
    pub fn all_queries_ordered(&self) -> [Vec<Query>; 6] {
        [
            self.advice_queries.clone(),
            self.permutation_queries.clone(),
            self.lookup_queries.clone(),
            self.fixed_queries.clone(),
            self.common_queries.clone(),
            self.vanishing_queries.clone(),
        ]
    }
}
