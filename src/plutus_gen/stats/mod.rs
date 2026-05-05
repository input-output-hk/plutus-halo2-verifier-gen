//! High level code for estimating the number of operations for a Halo2 verifier
//! PCS related code is in `pcs` module directly.

use blstrs::{G1Projective, Scalar};
use halo2_proofs::{
    plonk::VerifyingKey, poly::commitment::PolynomialCommitmentScheme, utils::SerdeFormat,
};

use crate::plutus_gen::extraction::data::{
    CircuitRepresentation, MsmOperations, ProofExtractionSteps, Query, RotationDescription,
    ScalarOperation,
};
use crate::plutus_gen::extraction::pcs::{ExtractPCS, PCSType};

use itertools::Itertools;
use std::collections::HashMap;

pub mod circuit_statistics;
use circuit_statistics::CircuitStatistics;

// Estimate the size of a verification key, with compressed G1 element.
// The VK does _not_ include the SRS _nor_ the PCS parameters
pub fn estimate_vk_size<PCS>(nb_public_inputs: usize, nb_advice: usize, nb_fixed: usize) -> usize
where
    PCS: ExtractPCS,
{
    let nb_permutations = nb_advice + if nb_public_inputs > 0 { 1 } else { 0 };

    let nb_commitments = {
        nb_fixed // selectors
            + nb_permutations // permutation
    };

    10 + nb_commitments * 48
}

// Estimate a _lower bound_ of the proof size.
// This is a lower bound as the number of evaluation points and set depends on the gates
pub fn estimate_proof_size<PCS>(
    nb_public_inputs: usize,
    nb_advice: usize,
    nb_fixed: usize,
    nb_lookups: usize,
    circuit_degree: usize,
) -> usize
where
    PCS: ExtractPCS,
{
    let nb_non_fixed = nb_advice + if nb_public_inputs > 0 { 1 } else { 0 };
    let nb_permutations = nb_non_fixed.div_ceil(circuit_degree - 2);

    let nb_commitments = {
        (nb_non_fixed -1) // Advice wires commitments, one fewer because of optimization
        + nb_permutations // Permutation commitments
        + 1 // Vanishing polynomial randomness
        + 3 * nb_lookups // Permutation input/table and lookup commitment
        + (circuit_degree - 1) // Vanishing polynomial splits
        + if PCS::pcs_type() == PCSType::Halo2MultiOpen {
            2 // f_commitment and pi_term
        } else if PCS::pcs_type() == PCSType::GWC19 {
            3 // w, we suppose we have at least 3 point sets (prev, current, next)
        } else {
            panic!("unknown PCS")
        }
    };

    let nb_scalars = {
        nb_non_fixed // advice wires evaluations, we assume a single eval per advice as a lower bound
        + nb_fixed // fixed wire evaluations
        + 1 // random evaluation
        + nb_non_fixed // permutation common evaluations
        + (nb_permutations * nb_permutations -1) // permutation cross terms, one fewer because of optimization
        + 5 * nb_lookups // product eval/next eal, permuted input, input inv and table
        + if PCS::pcs_type() == PCSType::Halo2MultiOpen {
            3 // q_eval, we suppose we have at least 3 point sets (prev, current, next)
        } else if PCS::pcs_type() == PCSType::GWC19 {
            0
        } else {
            panic!("unknown PCS")
        }
    };

    nb_commitments * 48 + nb_scalars * 32
}

// Estimate the cost of a verifier given a circuit
pub fn compute_verifier_code<PCS>(
    vk: &VerifyingKey<Scalar, PCS>,
    circuit: &CircuitRepresentation<PCS>,
) -> CircuitStatistics
where
    PCS: ExtractPCS + PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
    let size_proof = {
        // common information
        let (pes_commitments, pes_scalars) =
            circuit
                .proof_extraction_steps
                .iter()
                .fold((0, 0), |acc, pes| {
                    let res = pes.step_stat();
                    (acc.0 + res.0, acc.1 + res.1)
                });

        // PCS dependent information
        let (pcs_commitments, pcs_scalars) =
            circuit
                .pcs_extraction_steps
                .iter()
                .fold((0, 0), |acc, step| {
                    let res = PCS::step_stat(step);
                    (acc.0 + res.0, acc.1 + res.1)
                });

        let nb_commitments = pes_commitments + pcs_commitments;
        let nb_scalars = pes_scalars + pcs_scalars;

        nb_commitments * 48 + nb_scalars * 32
    };

    let mut stats = CircuitStatistics::new(
        size_proof,
        vk.bytes_length(SerdeFormat::Processed),
        circuit.proof_instantiation_data.public_inputs_count,
    );

    // Computating rotations for vanishing polynomial (1+ blinding factors)
    (0..=circuit.proof_instantiation_data.blinding_factors).for_each(|_| stats.rotate_omega());

    // Absorbing vk
    stats.common_scalar();

    // Absorbing number of PIs and each PI
    stats.common_scalar();
    stats.from_int_scalar();
    (1..=circuit.proof_instantiation_data.public_inputs_count).for_each(|_| stats.common_scalar());

    // PES
    circuit
        .proof_extraction_steps
        .iter()
        .chunk_by(|e| (*e).clone())
        .into_iter()
        .for_each(|(section_type, section)| match section_type {
            ProofExtractionSteps::AdviceCommitments => section.for_each(|_| stats.read_point()),
            ProofExtractionSteps::Theta => stats.squeeze_challenge(),
            ProofExtractionSteps::Beta => stats.squeeze_challenge(),
            ProofExtractionSteps::Gamma => stats.squeeze_challenge(),
            ProofExtractionSteps::PermutationsCommitted => section.for_each(|_| stats.read_point()),
            ProofExtractionSteps::VanishingRand => section.for_each(|_| stats.read_point()),
            ProofExtractionSteps::YCoordinate => stats.squeeze_challenge(),
            ProofExtractionSteps::VanishingSplit => section.for_each(|_| stats.read_point()),
            ProofExtractionSteps::XCoordinate => stats.squeeze_challenge(),
            ProofExtractionSteps::AdviceEval => section.for_each(|_| stats.read_scalar()),
            ProofExtractionSteps::FixedEval => section.for_each(|_| stats.read_scalar()),
            ProofExtractionSteps::RandomEval => stats.read_scalar(),
            ProofExtractionSteps::PermutationCommon => section.for_each(|_| stats.read_scalar()),
            ProofExtractionSteps::PermutationEval(_letter) => {
                section.for_each(|_| stats.read_scalar())
            }
            ProofExtractionSteps::SqueezeChallenge => panic!("no Squeeze Challenge supported"),
            ProofExtractionSteps::LookupPermuted => section.for_each(|_| {
                stats.read_point(); // permuted_input
                stats.read_point(); // permuted_table
            }),
            ProofExtractionSteps::LookupCommitment => section.for_each(|_| stats.read_point()),
            ProofExtractionSteps::LookupEval => section.for_each(|_| {
                stats.read_scalar(); // product_eval
                stats.read_scalar(); // product_eval_next
                stats.read_scalar(); // permuted_input_eval
                stats.read_scalar(); // permuted_input_inv_eval
                stats.read_scalar(); // permuted_table_eval
            }),
        });

    circuit
        .pcs_extraction_steps
        .iter()
        .for_each(|step| PCS::step_stat_operation(&mut stats, step));

    assert_eq!(stats.transcript_size, 0);

    // Computing powers of evaluation point
    stats.pow_scalar(); // x^n
    stats.rotate_omega(); // x_prev
    stats.rotate_omega(); // x_current
    stats.rotate_omega(); // x_next
    stats.rotate_omega(); // x_last

    // Computing Lagrange interpolation
    // evaluations_of_lagrange_polynomial
    stats.lagrange_polynomial_basis(1 + circuit.proof_instantiation_data.blinding_factors);
    // sum_of_evaluation_for_blinding_factors
    (1..=circuit.proof_instantiation_data.blinding_factors).for_each(|_| stats.add_scalar());
    // active rows: sub(scalarOne, add(last_evaluation, sum...))
    stats.add_scalar();
    stats.sub_scalar();
    // rotations_for_instances
    (1..=circuit.proof_instantiation_data.public_inputs_count).for_each(|_| stats.rotate_omega());
    // TODO lagrange_polynomial_instances
    stats.lagrange_polynomial_basis(circuit.proof_instantiation_data.public_inputs_count);
    // TODO instance_eval_1 if any
    stats.inner_product(circuit.proof_instantiation_data.public_inputs_count);

    circuit
        .expressions
        .compiled_gate_equations
        .iter()
        .for_each(|gate| stats.expression(gate));

    circuit
        .expressions
        .compiled_lookups_equations
        .0
        .iter()
        .for_each(|input_lookups| {
            input_lookups.iter().for_each(|lookup| {
                // Folding the expression
                stats.add_scalar();
                stats.mul_scalar();

                // Compiling the expression
                stats.expression(lookup);
            });
        });

    circuit
        .expressions
        .compiled_lookups_equations
        .1
        .iter()
        .for_each(|table_lookups| {
            table_lookups.iter().for_each(|lookup| {
                // Folding the expression
                stats.add_scalar();
                stats.mul_scalar();

                // Compiling the expression
                stats.expression(lookup);
            });
        });

    // Lookup equations
    (1..=circuit.expressions.compiled_lookups_equations.0.len()).for_each(|_| {
        // !l1 = evaluation_at_0 * (scalarOne - product_eval_1)
        stats.sub_scalar();
        stats.mul_scalar();

        // !l2 = last_evaluation * (product_eval_1 * product_eval_1 - product_eval_1)
        stats.mul_scalar();
        stats.sub_scalar();
        stats.mul_scalar();

        // !lookup_left_1 = product_eval_1 * (permuted_input_eval_1 + beta) * (permuted_table_eval_1 + gamma)
        stats.add_scalar();
        stats.add_scalar();
        stats.mul_scalar();
        stats.mul_scalar();

        // !lookup_right_1 = product_eval_1 * (lookup_input_eq1 + beta) * (lookup_table_eq1 + gamma)
        stats.add_scalar();
        stats.add_scalar();
        stats.mul_scalar();
        stats.mul_scalar();

        // !l3 = (lookup_left_1 - lookup_right_1) * active_rows
        stats.sub_scalar();
        stats.mul_scalar();

        // !l4 = evaluation_at_0 * (permuted_input_eval_1 - permuted_table_eval_1)
        stats.sub_scalar();
        stats.mul_scalar();

        // !l5 = (permuted_input_eval_1 - permuted_table_eval_1)
        //     * &(permuted_input_eval_1 - permuted_input_inv_eval_1) * active_rows
        stats.sub_scalar();
        stats.mul_scalar();
        stats.sub_scalar();
        stats.mul_scalar();
    });

    // Permutation evaluations
    circuit
        .expressions
        .permutations_evaluated_terms
        .iter()
        .for_each(|perm_exp| stats.scalar_expression(perm_exp));

    // Permutation left terms
    let mut sets_lhs: HashMap<char, String> = HashMap::new();
    {
        // Handling terms in chunks
        circuit
            .expressions
            .permutation_terms_left
            .iter()
            .for_each(|(set, exp)| {
                if sets_lhs.contains_key(set) {
                    stats.mul_scalar();
                } else {
                    sets_lhs.insert(*set, String::new());
                }
                stats.scalar_expression(exp);
            });
        // Batching chunks together
        sets_lhs.iter().for_each(|_| stats.mul_scalar());
    }

    // Permutation right terms
    let mut sets_rhs: HashMap<char, String> = HashMap::new();
    {
        // Handling terms in chunks
        circuit
            .expressions
            .permutation_terms_right
            .iter()
            .for_each(|(set, exp)| {
                if sets_rhs.contains_key(set) {
                    stats.mul_scalar();
                } else {
                    sets_rhs.insert(*set, String::new());
                }
                stats.scalar_expression(exp);
            });
        // Batching chunks together
        sets_rhs.iter().for_each(|_| stats.mul_scalar());
    }

    // Combining left and right permutations
    assert_eq!(sets_lhs.len(), sets_rhs.len());
    (1..=sets_lhs.len()).for_each(|_| {
        // let permutations{} = mul(sub(left_set{}, right_set{}), sub({}, add({}, sum_of_evaluation_for_blinding_factors
        stats.mul_scalar();
        stats.sub_scalar();
        stats.sub_scalar();
        stats.add_scalar();
    });

    let mut total_nb_expressions = 0;
    total_nb_expressions += circuit.expressions.compiled_gate_equations.len();
    total_nb_expressions += circuit.expressions.permutations_evaluated_terms.len();
    total_nb_expressions += sets_lhs.len();
    total_nb_expressions += circuit.expressions.compiled_lookups_equations.0.len() * 5;
    (1..=total_nb_expressions).for_each(|_| {
        stats.add_scalar();
        stats.mul_scalar();
    });

    // inverted = recip_eea(sub(xn, scalarOne))
    stats.sub_scalar();
    stats.inv_scalar();
    // vanishing_s = mul(hEval, inverted)
    stats.mul_scalar();

    circuit
        .expressions
        .h_commitments
        .iter()
        .for_each(|(_name, exp)| stats.point_expression(exp));

    // compress(vanishing_g) — needed to pass the computed point into PCS commitment data
    stats.compress_point();

    let (unique_grouped_points, commitment_data) = PCS::precompute_intermediate_sets(&circuit);

    if PCS::pcs_type() == PCSType::Halo2MultiOpen {
        let num_point_sets = unique_grouped_points.len();
        let max_commitments_per_points_set = (0..num_point_sets)
            .map(|idx| {
                commitment_data
                    .iter()
                    .filter(|cd| cd.point_set_index == idx)
                    .count()
            })
            .max()
            .unwrap_or(0);

        // Powers of x1: powers(HALO2_X1_POWERS_COUNT, x1)
        (2..=max_commitments_per_points_set).for_each(|_| stats.mul_scalar());

        // Powers of x4: powers(HALO2_X4_POWERS_COUNT, x4)
        (2..=num_point_sets + 1).for_each(|_| stats.mul_scalar());

        // TODO: count compute_msm operations (decompress + scale + add per commitment)
    }

    if PCS::pcs_type() == PCSType::GWC19 {
        let kzg_gwc19_intermediate_sets =
            construct_intermediate_sets(circuit.queries.all_ordered());
        let (left, right) = construct_msm(kzg_gwc19_intermediate_sets);

        let optimized_left = left.flatten_msm().optimize_msm();
        let optimized_right = right.flatten_msm().optimize_msm();

        stats.msm_operation(&optimized_left);
        stats.msm_operation(&optimized_right);

        // Computing all powers of v
        let max_v_power = optimized_left
            .find_max_power('v')
            .max(optimized_right.find_max_power('v'));
        (2..=max_v_power).for_each(|_| stats.mul_scalar());

        // Computing all powers of u
        let max_u_power = optimized_left
            .find_max_power('u')
            .max(optimized_right.find_max_power('u'));
        (2..=max_u_power).for_each(|_| stats.mul_scalar());
    }

    stats
}

pub fn emit_vk_code<PCS>(circuit: &CircuitRepresentation<PCS>)
where
    PCS: ExtractPCS,
{

    // let points = circuit
    //     .proof_instantiation_data
    //     .fixed_commitments
    //     .iter()
    //     .cloned()
    //     .map(|g| hex::encode(g.to_bytes()));

    // let points = points
    //     .enumerate()
    //     .map(|(idx, g1_encoded)| {
    //         format!(
    //             "pub const f{}_commitment: ByteArray = #\"{}\"",
    //             idx + 1,
    //             g1_encoded
    //         )
    //     })
    //     .join("\n");

    // data.insert("FIXED_COMMITMENTS".to_string(), points);

    // let points = circuit
    //     .proof_instantiation_data
    //     .permutation_commitments
    //     .iter()
    //     .cloned()
    //     .map(|g| hex::encode(g.to_bytes()));

    // let points = points
    //     .enumerate()
    //     .map(|(idx, g1_encoded)| {
    //         format!(
    //             "pub const p{}_commitment: ByteArray = #\"{}\"",
    //             idx + 1,
    //             g1_encoded
    //         )
    //     })
    //     .join("\n");

    // data.insert("PERMUTATION_COMMITMENTS".to_string(), points);

    // let compressed_sg2 = hex::encode(circuit.proof_instantiation_data.s_g2.to_bytes());

    // data.insert(
    //     "G2_DEFINITIONS".to_string(),
    //     format!("\"{}\"", compressed_sg2),
    // );
    // data.insert(
    //     "OMEGA".to_string(),
    //     hex::encode(circuit.proof_instantiation_data.omega.to_bytes_be()),
    // );
    // data.insert(
    //     "OMEGA_INV".to_string(),
    //     hex::encode(
    //         circuit
    //             .proof_instantiation_data
    //             .inverted_omega
    //             .to_bytes_be(),
    //     ),
    // );
    // data.insert(
    //     "BARYCENTRIC_WEIGHT".to_string(),
    //     hex::encode(
    //         circuit
    //             .proof_instantiation_data
    //             .barycentric_weight
    //             .to_bytes_be(),
    //     ),
    // );
    // data.insert(
    //     "TRANSCRIPT_REP".to_string(),
    //     hex::encode(
    //         circuit
    //             .proof_instantiation_data
    //             .transcript_representation
    //             .to_bytes_be(),
    //     ),
    // );
    // data.insert(
    //     "BLINDING_FACTORS".to_string(),
    //     circuit
    //         .proof_instantiation_data
    //         .blinding_factors
    //         .to_string(),
    // );

    // let fixed_commitments = circuit.proof_instantiation_data.fixed_commitments.len();

    // let permutation_commitments = circuit
    //     .proof_instantiation_data
    //     .permutation_commitments
    //     .len();

    // let fixed = (1..=fixed_commitments).map(|idx| {
    //     format!(
    //         "\tlet f{idx}_commitment = decompress(f{idx}_commitment)\n\
    //         \texpect f{idx}_commitment == f{idx}_commitment"
    //     )
    // });
    // let permutations = (1..=permutation_commitments).map(|idx| {
    //     format!(
    //         "\tlet p{idx}_commitment = decompress(p{idx}_commitment)\n\
    //         \texpect p{idx}_commitment == p{idx}_commitment"
    //     )
    // });

    // let budget_check = fixed
    //     .chain(permutations)
    //     .chain(once("    expect g2_const == g2_const".to_string()))
    //     .join("\n");

    // data.insert("BUDGET_CHECK".to_string(), budget_check);

    // let mut handlebars = Handlebars::new();
    // handlebars.set_strict_mode(true);
    // handlebars.register_template_file("aiken_template", template_file)?;
    // let mut output_file = File::create(aiken_file)?;
    // handlebars.render_to_write("aiken_template", &data, &mut output_file)?;
    // handlebars.render("aiken_template", &data)
}

fn construct_intermediate_sets(queries: [Vec<Query>; 6]) -> Vec<(Vec<Query>, RotationDescription)> {
    let mut point_query_map: Vec<(RotationDescription, Vec<Query>)> = Vec::new();
    for query in queries.iter().flatten() {
        if let Some(pos) = point_query_map
            .iter()
            .position(|(point, _)| *point == query.point)
        {
            let (_, queries) = &mut point_query_map[pos];
            queries.push(*query);
        } else {
            point_query_map.push((query.point, vec![*query]));
        }
    }

    point_query_map
        .into_iter()
        .map(|(point, queries)| (queries, point))
        .collect()
}

// symbolic representation of powers of specific scalar
fn powers(name: char) -> impl Iterator<Item = ScalarOperation> {
    (0..).map(move |idx| ScalarOperation::Power(name, idx))
}

// This is done in Plinth with template haskell since there is no macro language for aiken
// constructing final MSM was reimplemented with pure code generation
// to make it easier to debug this function is 1:1 analog to multi_prepare
// in src/poly/gwc_kzg/mod.rs
// in https://github.com/input-output-hk/halo2/blob/gwc19_kzg/src/poly/gwc_kzg/mod.rs#L142-L212
// but was translated to build MSM description instead of calculating one
fn construct_msm(
    commitment_data: Vec<(Vec<Query>, RotationDescription)>,
) -> (MsmOperations, MsmOperations) {
    let w_count = commitment_data.len();

    let mut commitment_multi = MsmOperations::Empty;
    let mut eval_multi = ScalarOperation::Zero;

    let mut witness = MsmOperations::Empty;
    let mut witness_with_aux = MsmOperations::Empty;

    for ((commitment_at_a_point, wi), power_of_u) in
        commitment_data.iter().zip(0..w_count).zip(powers('u'))
    {
        let (queries, point) = commitment_at_a_point;

        assert!(!queries.is_empty());
        let z = point;

        let (commitment_batch, eval_batch) = queries
            .iter()
            .zip(powers('v'))
            .map(|(query, power_of_v)| {
                assert_eq!(query.point, *z);

                let commitment = query.commitment;
                let mut msm = MsmOperations::Empty;
                msm = MsmOperations::Append(Box::new(msm), power_of_v.clone(), commitment);

                let eval = ScalarOperation::Mul(Box::new(power_of_v), query.evaluation);

                (msm, eval)
            })
            .reduce(|(commitment_acc, eval_acc), (commitment, eval)| {
                (
                    MsmOperations::Add(Box::new(commitment_acc.clone()), Box::new(commitment)),
                    ScalarOperation::Add(Box::new(eval_acc), Box::new(eval)),
                )
            })
            .unwrap();

        let commitment_batch =
            MsmOperations::Scale(Box::new(commitment_batch.clone()), power_of_u.clone());
        commitment_multi =
            MsmOperations::Add(Box::new(commitment_multi), Box::new(commitment_batch));
        eval_multi = ScalarOperation::Add(
            Box::new(eval_multi),
            Box::new(ScalarOperation::MulS(
                Box::new(power_of_u.clone()),
                Box::new(eval_batch),
            )),
        );

        witness_with_aux = MsmOperations::AppendW(
            Box::new(witness_with_aux),
            ScalarOperation::MulS(
                Box::new(power_of_u.clone()),
                Box::new(ScalarOperation::Rotation(*z)),
            ),
            wi,
        );
        witness = MsmOperations::AppendW(Box::new(witness), power_of_u, wi);
    }

    let left: MsmOperations = witness;
    let mut right: MsmOperations = MsmOperations::Empty;

    right = MsmOperations::Add(Box::new(right), Box::new(witness_with_aux));
    right = MsmOperations::Add(Box::new(right), Box::new(commitment_multi));
    right = MsmOperations::AppendNegatedG1(Box::new(right), eval_multi);

    (left, right)
}
