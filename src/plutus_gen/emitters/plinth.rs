//! All functions related to writing Plinth code

use crate::plutus_gen::extraction::data::languages::plinth::*;
use crate::plutus_gen::extraction::data::{
    CircuitRepresentation, ProofExtractionSteps, RotationDescription, constants::*,
};

use group::GroupEncoding;
use group::prime::PrimeCurveAffine;
use handlebars::{Handlebars, RenderError};
use itertools::Itertools;
use log::debug;
use std::{collections::HashMap, fs::File, path::Path};

pub fn emit_verifier_code(
    template_file: &Path, // haskell mustashe template
    haskell_file: &Path,  // generated haskell file, output
    circuit: &CircuitRepresentation,
) -> Result<String, RenderError> {
    let letters = 'a'..='z';
    let proof_extraction: Vec<_> = circuit
        .proof_extraction_steps
        .iter()
        .chunk_by(|e| (*e).clone())
        .into_iter()
        .map(|(section_type, section)| match section_type {
            ProofExtractionSteps::AdviceCommitments => section
                .enumerate()
                .map(|(number, _advice)| format!("  !a{} <- M.readPoint\n", number + 1))
                .join(""),
            ProofExtractionSteps::Theta => "  !theta <- M.squeezeChallenge\n".to_string(),
            ProofExtractionSteps::Beta => "  !beta <- M.squeezeChallenge\n".to_string(),
            ProofExtractionSteps::Gamma => "  !gamma <- M.squeezeChallenge\n".to_string(),
            ProofExtractionSteps::PermutationsCommitted => section
                .zip(letters.clone())
                .map(|(_permutation, letter)| {
                    format!("  !permutations_committed_{} <- M.readPoint\n", letter)
                })
                .join(""),
            ProofExtractionSteps::VanishingRand => "  !vanishingRand <- M.readPoint\n".to_string(),
            ProofExtractionSteps::YCoordinate => "  !y <- M.squeezeChallenge\n".to_string(),
            ProofExtractionSteps::VanishingSplit => section
                .enumerate()
                .map(|(number, _vanishing_split)| {
                    format!("  !vanishingSplit_{} <- M.readPoint\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::XCoordinate => "  !x <- M.squeezeChallenge\n".to_string(),
            ProofExtractionSteps::AdviceEval => section
                .enumerate()
                .map(|(number, _advice_eval)| {
                    format!("  !adviceEval{} <- M.readScalar\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::FixedEval => section
                .enumerate()
                .map(|(number, _fixed_eval)| {
                    format!("  !fixedEval{} <- M.readScalar\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::RandomEval => "  !randomEval <- M.readScalar\n".to_string(),
            ProofExtractionSteps::PermutationCommon => section
                .enumerate()
                .map(|(number, _permutation_common)| {
                    format!("  !permutationCommon{} <- M.readScalar\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::PermutationEval(letter) => section
                .enumerate()
                .map(|(n, _)| format!("  !{} <- M.readScalar\n", perm_eval_str(&letter, n + 1)))
                .join(""),
            ProofExtractionSteps::SqueezeChallenge => panic!("not squeezeChallenge supported"),
            ProofExtractionSteps::LookupPermuted => section
                .enumerate()
                .map(|(number, _lookup_permuted)| {
                    format!("  !permutedInput{} <- M.readPoint\n", number + 1)
                        + &format!("  !permutedTable{} <- M.readPoint\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::LookupCommitment => section
                .enumerate()
                .map(|(number, _lookup_commitment)| {
                    format!("  !lookupCommitment{} <- M.readPoint\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::LookupEval => section
                .enumerate()
                .map(|(number, _permutation_common)| {
                    format!("  !product_eval_{} <- M.readScalar\n", number + 1)
                        + &format!("  !product_next_eval_{} <- M.readScalar\n", number + 1)
                        + &format!("  !permuted_input_eval_{} <- M.readScalar\n", number + 1)
                        + &format!(
                            "  !permuted_input_inv_eval_{} <- M.readScalar\n",
                            number + 1
                        )
                        + &format!("  !permuted_table_eval_{} <- M.readScalar\n", number + 1)
                })
                .join(""),
            // section for halo2 multi open version of KZG
            ProofExtractionSteps::X1 => "  !x1 <- M.squeezeChallenge\n".to_string(),
            ProofExtractionSteps::X2 => "  !x2 <- M.squeezeChallenge\n".to_string(),
            ProofExtractionSteps::X3 => "  !x3 <- M.squeezeChallenge\n".to_string(),
            ProofExtractionSteps::X4 => "  !x4 <- M.squeezeChallenge\n".to_string(),
            ProofExtractionSteps::Trash => "  !trash_challenge <- M.squeezeChallenge\n".to_string(),
            ProofExtractionSteps::FCommitment => "  !f_commitment <- M.readPoint\n".to_string(),
            ProofExtractionSteps::PI => "  !pi_term <- M.readPoint\n".to_string(),
            ProofExtractionSteps::QEvals => section
                .enumerate()
                .map(|(number, _permutation_common)| {
                    format!("  !q_eval_on_x3_{} <- M.readScalar\n", number + 1)
                })
                .join(""),
        })
        .collect();

    let mut data: HashMap<String, String> = HashMap::new(); // data to bind to mustache template

    data.insert(
        "PUBLIC_INPUTS_COUNT".to_string(),
        circuit.public_inputs.to_string(),
    );

    let proof_extraction_stage = proof_extraction.join("");
    data.insert("PES".to_string(), proof_extraction_stage);

    data.insert(
        "X_EXPONENT".to_string(),
        circuit.instantiation_data.n_coefficient.to_string(),
    );

    let gates = circuit
        .expressions
        .compiled_gate_equations
        .iter()
        .enumerate()
        .map(|(id, gate)| {
            format!(
                "      !gate_eq{:?} = {}\n",
                id + 1,
                gate.compile_expression()
            )
        })
        .join("");
    data.insert("GATES".to_string(), gates);

    let lookup_tables = circuit
        .expressions
        .compiled_lookups_equations
        .1
        .iter()
        .enumerate()
        .map(|(id, gate)| {
            format!(
                "      !lookup_table_eq{:?} = {}\n",
                id + 1,
                combine_plinth_expressions(gate.clone())
            )
        })
        .join("");
    data.insert("LOOKUP_TABLES_EXPRESSIONS".to_string(), lookup_tables);

    let lookup_inputs = circuit
        .expressions
        .compiled_lookups_equations
        .0
        .iter()
        .enumerate()
        .map(|(id, gate)| {
            format!(
                "      !lookup_input_eq{:?} = {}\n",
                id + 1,
                combine_plinth_expressions(gate.clone())
            )
        })
        .join("");
    data.insert("LOOKUP_INPUTS_EXPRESSIONS".to_string(), lookup_inputs);

    let lookup_equations = (1..=circuit.expressions.compiled_lookups_equations.0.len())
        .map(|id| {
            // !l1 = evaluation_at_0 * (scalarOne - product_eval_1)
            // !l2 = last_evaluation * (product_eval_1 * product_eval_1 - product_eval_1)
            // 
            // !lookup_left_1 = product_eval_1 * (permuted_input_eval_1 + beta) * (permuted_table_eval_1 + gamma)
            // !lookup_right_1 = product_eval_1 * (lookup_input_eq1 + beta) * (lookup_table_eq1 + gamma)
            // 
            // !l3 = (lookup_left_1 - lookup_right_1) * active_rows
            // 
            // !l4 = evaluation_at_0 * (permuted_input_eval_1 - permuted_table_eval_1)
            // !l5 = (permuted_input_eval_1 - permuted_table_eval_1)
            //     * &(permuted_input_eval_1 - permuted_input_inv_eval_1) * active_rows

            let l1 = format!("{} * ({} - product_eval_{})", EVAL_0_STR, ONE_STR, id);
            let l2 = format!("{} * (product_eval_{} * product_eval_{} - product_eval_{})", EVAL_LAST_STR, id, id, id);
            let left = format!("product_next_eval_{} * (permuted_input_eval_{} + beta) * (permuted_table_eval_{} + gamma)", id, id, id);
            let right = format!("product_eval_{} * (lookup_input_eq{} + beta) * (lookup_table_eq{} + gamma)", id, id, id);
            let l3 = format!("(lookup_left_{} - lookup_right_{}) * active_rows", id, id);
            let l4 = format!("{} * (permuted_input_eval_{} - permuted_table_eval_{})", EVAL_0_STR, id, id);
            let l5 = format!("(permuted_input_eval_{} - permuted_table_eval_{}) * (permuted_input_eval_{} - permuted_input_inv_eval_{}) * active_rows", id, id, id, id);

            format!("      !lookup_expression_1_{} = {}\n", id, l1) +
                format!("      !lookup_expression_2_{} = {}\n", id, l2).as_str() +
                format!("      !lookup_left_{} = {}\n", id, left).as_str() +
                format!("      !lookup_right_{} = {}\n", id, right).as_str() +
                format!("      !lookup_expression_3_{} = {}\n", id, l3).as_str() +
                format!("      !lookup_expression_4_{} = {}\n", id, l4).as_str() +
                format!("      !lookup_expression_5_{} = {}\n\n\n", id, l5).as_str()
        })
        .join("");

    data.insert("LOOKUPS".to_string(), lookup_equations);

    let permutation_evals = circuit
        .expressions
        .permutations_evaluated_terms
        .iter()
        .enumerate()
        .map(|(id, expression)| {
            let term = expression.compile_expression();
            format!("      !term{:?} = {}\n", id + 1, term)
        })
        .join("");
    data.insert("PERMUTATIONS_EVALS".to_string(), permutation_evals);

    let mut sets_lhs: HashMap<char, String> = HashMap::new();
    let mut sets_rhs: HashMap<char, String> = HashMap::new();

    let permutation_lhs = circuit
        .expressions
        .permutation_terms_left
        .iter()
        .enumerate()
        .map(|(id, (set, expression))| {
            if sets_lhs.contains_key(set) {
                let existing = sets_lhs
                    .get(set)
                    .unwrap_or_else(|| panic!("set {} not found", set));
                sets_lhs.insert(*set, format!("{} * left{:?}", existing, id + 1));
            } else {
                sets_lhs.insert(*set, format!("left{:?}", id + 1));
            };
            let term = expression.compile_expression();
            format!("      !left{:?} = {} --part of set {}\n", id + 1, term, set)
        })
        .join("");
    data.insert("PERMUTATIONS_LHS".to_string(), permutation_lhs);

    let lhf_sets = sets_lhs
        .iter()
        .sorted_by_key(|(c, _)| **c)
        .enumerate()
        .map(|(set_number, (set_id, terms))| {
            format!(
                "      !left_set{:?} = {} * {} \n",
                set_number + 1,
                perm_eval_str(set_id, 2),
                terms
            )
        })
        .join("");
    data.insert("LHS_SETS".to_string(), lhf_sets);

    let permutation_rhs = circuit
        .expressions
        .permutation_terms_right
        .iter()
        .enumerate()
        .map(|(id, (set, expression))| {
            if sets_rhs.contains_key(set) {
                let existing = sets_rhs
                    .get(set)
                    .unwrap_or_else(|| panic!("set {} not found", set));
                sets_rhs.insert(*set, format!("{} * right{:?}", existing, id + 1));
            } else {
                sets_rhs.insert(*set, format!("right{:?}", id + 1));
            };
            let term = expression.compile_expression();
            format!(
                "      !right{:?} = {} --part of set {}\n",
                id + 1,
                term,
                set
            )
        })
        .join("");
    data.insert("PERMUTATIONS_RHS".to_string(), permutation_rhs);

    let rhf_sets = sets_rhs
        .iter()
        .sorted_by_key(|(c, _)| **c)
        .enumerate()
        .map(|(set_number, (set_id, terms))| {
            format!(
                "      !right_set{:?} = {} * {} \n",
                set_number + 1,
                perm_eval_str(set_id, 1),
                terms
            )
        })
        .join("");
    data.insert("RHS_SETS".to_string(), rhf_sets);

    let permutations_combined = if sets_lhs.len() == sets_rhs.len() {
        let sets_number = sets_lhs.len();
        (1..=sets_number).map(|n| {
            format!("      !permutations{} = (left_set{} - right_set{}) * ({} - ({} + sum_of_evaluation_for_blinding_factors))\n", n, n, n, ONE_STR, EVAL_LAST_STR)
        }).join("")
    } else {
        panic!("permutations sets have to be equal length")
    };

    data.insert("PERMUTATIONS_COMBINED".to_string(), permutations_combined);

    let gates_count = circuit.expressions.compiled_gate_equations.len();
    let permutations_eval_count = circuit.expressions.permutations_evaluated_terms.len();
    let sets_count = sets_lhs.len();
    let lookups_count = circuit.expressions.compiled_lookups_equations.0.len();

    let mut total_nb_expressions = 0;

    let mut vanishing_expressions = (1..=gates_count)
        .map(|n| format!("      !expression{} = gate_eq{}\n", n, n))
        .collect::<Vec<_>>();
    total_nb_expressions += gates_count;

    let expressions = (1..=permutations_eval_count)
        .map(|n| {
            format!(
                "      !expression{} = term{}\n",
                n + total_nb_expressions,
                n
            )
        })
        .collect::<Vec<_>>();
    vanishing_expressions.extend(expressions);
    total_nb_expressions += permutations_eval_count;

    let expressions = (1..=sets_count)
        .map(|n| {
            format!(
                "      !expression{} = permutations{}\n",
                n + total_nb_expressions,
                n
            )
        })
        .collect::<Vec<_>>();
    vanishing_expressions.extend(expressions);
    total_nb_expressions += sets_count;

    let expressions = (1..=lookups_count)
        .flat_map(|n| {
            [
                format!(
                    "      !expression{} = lookup_expression_1_{}\n",
                    ((n - 1) * 5) + 1 + total_nb_expressions,
                    n
                ),
                format!(
                    "      !expression{} = lookup_expression_2_{}\n",
                    ((n - 1) * 5) + 2 + total_nb_expressions,
                    n
                ),
                format!(
                    "      !expression{} = lookup_expression_3_{}\n",
                    ((n - 1) * 5) + 3 + total_nb_expressions,
                    n
                ),
                format!(
                    "      !expression{} = lookup_expression_4_{}\n",
                    ((n - 1) * 5) + 4 + total_nb_expressions,
                    n
                ),
                format!(
                    "      !expression{} = lookup_expression_5_{}\n",
                    ((n - 1) * 5) + 5 + total_nb_expressions,
                    n
                ),
            ]
        })
        .collect::<Vec<_>>();
    vanishing_expressions.extend(expressions);
    total_nb_expressions += lookups_count * 5;

    data.insert(
        "VANISHING_EXPRESSIONS".to_string(),
        vanishing_expressions.join(""),
    );

    let mut vanishing_evaluation = format!("({} * y + expression1)", ZERO_STR);
    for n in 2..=total_nb_expressions {
        vanishing_evaluation = format!("({} * y + expression{})", vanishing_evaluation, n)
    }
    let vanishing_evaluation = format!("      !hEval = {}\n", vanishing_evaluation);
    data.insert("VANISHING_EVALUATION".to_string(), vanishing_evaluation);

    let h_commitments = circuit
        .expressions
        .h_commitments
        .iter()
        .map(|(variable_name, expression)| {
            let term = expression.compile_expression();
            format!("      !{} = {}\n", variable_name, term)
        })
        .join("");
    data.insert("H_COMMITMENTS".to_string(), h_commitments);

    let advice_queries = circuit
        .queries
        .advice
        .iter()
        .enumerate()
        .map(|(number, query)| {
            format!(
                "      !a{}_query = MinimalVerifierQuery {} {}\n",
                number + 1,
                query.commitment.compile_expression(),
                query.evaluation.compile_expression()
            )
        })
        .join("");
    data.insert("ADVICE_QUERIES".to_string(), advice_queries);

    let fixed_queries = circuit
        .queries
        .fixed
        .iter()
        .enumerate()
        .map(|(number, query)| {
            format!(
                "      !f{}_query = MinimalVerifierQuery {} {}\n",
                number + 1,
                query.commitment.compile_expression(),
                query.evaluation.compile_expression()
            )
        })
        .join("");
    data.insert("FIXED_QUERIES".to_string(), fixed_queries);

    let permutation_queries = circuit
        .queries
        .permutation
        .iter()
        .enumerate()
        .map(|(number, query)| {
            format!(
                "      !permutations_query{} = MinimalVerifierQuery {} {}\n",
                number + 1,
                query.commitment.compile_expression(),
                query.evaluation.compile_expression()
            )
        })
        .join("");
    data.insert("PERMUTATION_QUERIES".to_string(), permutation_queries);

    let common_queries = circuit
        .queries
        .common
        .iter()
        .enumerate()
        .map(|(number, query)| {
            format!(
                "      !p{}_query = MinimalVerifierQuery {} {}\n",
                number + 1,
                query.commitment.compile_expression(),
                query.evaluation.compile_expression()
            )
        })
        .join("");
    data.insert("COMMON_QUERIES".to_string(), common_queries);

    let (unique_grouped_points, commitment_data) = circuit.precompute_intermediate_sets();

    // Precompute maximum number of commitments queried for any points set,
    // it will define the number of X1 powers that we would need to compute during verification
    let point_sets_indexes: Vec<usize> = (0..unique_grouped_points.len()).collect();
    let max_commitments_per_points_set = point_sets_indexes
        .iter()
        .map(|&idx| {
            commitment_data
                .iter()
                .filter(|cd| cd.point_set_index == idx)
                .count()
        })
        .max()
        .unwrap_or(0);
    data.insert(
        "X1_POWERS_COUNT".to_string(),
        max_commitments_per_points_set.to_string(),
    );

    data.insert(
        "X4_POWERS_COUNT".to_string(),
        (point_sets_indexes.len() + 1).to_string(),
    );

    let commitment_data = commitment_data
        .iter()
        .map(|commitment_data| {
            format!(
                "{}, {}, [{}], [{}]",
                commitment_data.commitment.compile_expression(),
                commitment_data.point_set_index,
                commitment_data
                    .points
                    .iter()
                    .map(RotationDescription::to_string)
                    .join(","),
                commitment_data
                    .evaluations
                    .iter()
                    .map(PlinthExpression::compile_expression)
                    .join(",")
            )
        })
        .join("),(");

    let commitment_map = format!("      !commitment_data = [({})]", commitment_data);
    data.insert("COMMITMENT_MAP".to_string(), commitment_map);

    let point_sets = unique_grouped_points
        .iter()
        .map(|set| set.iter().map(RotationDescription::to_string).join(","))
        .join("],[");

    let point_sets = format!("      !point_sets = [[{}]]", point_sets);
    data.insert("POINT_SETS".to_string(), point_sets);

    let common_queries = circuit
        .queries
        .lookup
        .iter()
        .enumerate()
        .map(|(number, query)| {
            format!(
                "      !l{}_query = MinimalVerifierQuery {} {}\n",
                number + 1,
                query.commitment.compile_expression(),
                query.evaluation.compile_expression()
            )
        })
        .join("");
    data.insert("LOOKUP_QUERIES".to_string(), common_queries);

    //  NameAnn 'x_current 'a1_query
    let msm_advice_queries = circuit
        .queries
        .advice
        .iter()
        .enumerate()
        .map(|(number, query)| {
            let rotation = query.point.to_string();
            format!(
                "              NameAnn '{} 'a{}_query ,\n",
                rotation,
                number + 1
            )
        })
        .join("");
    data.insert("MSM_ADVICE_QUERIES".to_string(), msm_advice_queries);

    let msm_permutation_queries = circuit
        .queries
        .permutation
        .iter()
        .enumerate()
        .map(|(number, query)| {
            let rotation = query.point.to_string();
            format!(
                "              NameAnn '{} 'permutations_query{} ,\n",
                rotation,
                number + 1
            )
        })
        .join("");
    data.insert(
        "MSM_PERMUTATION_QUERIES".to_string(),
        msm_permutation_queries,
    );

    let msm_fixed_queries = circuit
        .queries
        .fixed
        .iter()
        .enumerate()
        .map(|(number, query)| {
            let rotation = query.point.to_string();
            format!(
                "              NameAnn '{} 'f{}_query ,\n",
                rotation,
                number + 1
            )
        })
        .join("");
    data.insert("MSM_FIXED_QUERIES".to_string(), msm_fixed_queries);

    let msm_common_queries = circuit
        .queries
        .common
        .iter()
        .enumerate()
        .map(|(number, query)| {
            let rotation = query.point.to_string();
            format!(
                "              NameAnn '{} 'p{}_query ,\n",
                rotation,
                number + 1
            )
        })
        .join("");

    data.insert("MSM_COMMON_QUERIES".to_string(), msm_common_queries);

    let msm_lookup_queries = circuit
        .queries
        .lookup
        .iter()
        .enumerate()
        .map(|(number, query)| {
            let rotation = query.point.to_string();
            format!(
                "              NameAnn '{} 'l{}_query ,\n",
                rotation,
                number + 1
            )
        })
        .join("");

    data.insert("MSM_LOOKUP_QUERIES".to_string(), msm_lookup_queries);

    // ------
    // case for halo2 multi open version of KZG
    let q_evaluations = (1..=circuit.instantiation_data.q_evaluations_count)
        .map(|n| format!("q_eval_on_x3_{}", n))
        .join(", ");
    data.insert("Q_EVALS_FROM_PROOF".to_string(), q_evaluations);
    // ------

    let state = vec![];
    let rotation_order = circuit
        .queries
        .all_ordered()
        .iter()
        .flatten()
        .map(|query| &query.point)
        .scan(state, |s, e| {
            if !s.contains(e) {
                s.push(e.clone())
            }
            Some(s.clone())
        })
        .last()
        .expect("There should be at least one query");

    let rotation_order: Vec<_> = rotation_order
        .iter()
        .map(RotationDescription::to_string)
        .collect();

    let x_values = rotation_order
        .iter()
        .map(|n| format!("              '{}", n))
        .join(" ,\n");
    data.insert("X_ROTATIONS".to_string(), x_values);

    let fixed_commitments_lifts = (1..=circuit.instantiation_data.fixed_commitments.len()).map(|id| {
        format!("f{}_commitment :: BuiltinBLS12_381_G1_Element\nf{}_commitment = $(lift VKConstants.f{}_commitment)\n\n", id, id, id)
    }).join("");
    let permutation_commitments_lifts = (1..=circuit.instantiation_data.permutation_commitments.len()).map(|id| {
        format!("p{}_commitment :: BuiltinBLS12_381_G1_Element\np{}_commitment = $(lift VKConstants.p{}_commitment)\n\n", id, id, id)
    }).join("");
    let public_inputs = (1..=circuit.instantiation_data.public_inputs_count)
        .map(|n| format!("  !i{} <- M.commonScalar p{}\n", n, n))
        .join("");

    let public_inputs_types = (1..=circuit.instantiation_data.public_inputs_count)
        .map(|_| "Scalar ->".to_string())
        .join(" ");
    let public_inputs_names = (1..=circuit.instantiation_data.public_inputs_count)
        .map(|n| format!("p{}", n))
        .join(" ");

    let public_inputs_lagrange = (1..=circuit.instantiation_data.public_inputs_count)
        .map(|n| format!("i{}", n))
        .join(", ");

    data.insert(
        "FIXED_COMMITMENT_LIFTS".to_string(),
        fixed_commitments_lifts,
    );
    data.insert(
        "PERMUTATION_COMMITMENT_LIFTS".to_string(),
        permutation_commitments_lifts,
    );

    data.insert("PUBLIC_INPUTS_TYPES".to_string(), public_inputs_types);
    data.insert("PUBLIC_INPUTS_NAMES".to_string(), public_inputs_names);

    data.insert("PUBLIC_INPUTS".to_string(), public_inputs);
    data.insert("PUBLIC_INPUTS_LAGRANGE".to_string(), public_inputs_lagrange);

    // Include traces only in debug mode, because they increase cost of the Plutus verifier
    #[cfg(feature = "plutus_debug")]
    {
        let constants_tracing = [
            "(\"theta\", BlsUtils.traceScalar theta)",
            "(\"beta\", BlsUtils.traceScalar beta)",
            "(\"gamma\", BlsUtils.traceScalar gamma)",
            "(\"x_prev\", BlsUtils.traceScalar x_prev)",
            "(\"x_current\", BlsUtils.traceScalar x_current)",
            "(\"x_next\", BlsUtils.traceScalar x_next)",
            "(\"x_last\", BlsUtils.traceScalar x_last)",
            "(\"x\", BlsUtils.traceScalar x)",
            "(\"y\", BlsUtils.traceScalar y)",
            "(\"hEval\", BlsUtils.traceScalar hEval)",
            "(\"vanishing_s\", BlsUtils.traceScalar vanishing_s)",
            "(\"vanishing_g\", BlsUtils.traceG1 vanishing_g)",
            "(\"s_g2\", BlsUtils.traceG2 s_g2)",
            "(\"el\", BlsUtils.traceG1 el)",
            "(\"er\", BlsUtils.traceG1 er)",
            "(\"vanishing_query\", BlsUtils.traceMVQ vanishing_query x_current)",
            "(\"random_query\", BlsUtils.traceMVQ random_query x_current)",
        ]
        .to_vec()
        .iter()
        .map(|e| e.to_string())
        .collect();

        let gates_traces: Vec<_> = (1..=gates_count).map(|e| format!("gate_eq{}", e)).collect();
        let expressions_traces: Vec<_> = (1..=expressions_count)
            .map(|e| format!("expression{}", e))
            .collect();

        let advice_queries_traces: Vec<_> = circuit
            .queries
            .advice
            .iter()
            .enumerate()
            .map(|(q, idx)| (format!("a{}_query", idx), q.point.to_string()))
            .collect();

        let fixed_queries_traces: Vec<_> = circuit
            .queries
            .fixed
            .iter()
            .enumerate()
            .map(|(q, idx)| (format!("f{}_query", idx), q.point.to_string()))
            .collect();

        let permutation_queries_traces: Vec<_> = circuit
            .queries
            .permutation
            .iter()
            .enumerate()
            .map(|(q, idx)| (format!("permutations_query{}", idx), q.point.to_string()))
            .collect();

        let common_queries_traces: Vec<_> = circuit
            .queries
            .common
            .iter()
            .enumerate()
            .map(|(q, idx)| (format!("p{}_query", idx), q.point.to_string()))
            .collect();

        let lookups_queries_traces: Vec<_> = circuit
            .queries
            .lookup
            .iter()
            .enumerate()
            .map(|(q, idx)| (format!("l{}_query", idx), q.point.to_string()))
            .collect();

        let scalar_traces: Vec<_> = [gates_traces, expressions_traces]
            .iter()
            .flatten()
            .map(|e| format!("(\"{}\", BlsUtils.traceScalar {})", e, e))
            .collect();
        let mvq_traces: Vec<_> = [
            advice_queries_traces,
            fixed_queries_traces,
            permutation_queries_traces,
            common_queries_traces,
            lookups_queries_traces,
        ]
        .iter()
        .flatten()
        .map(|(e, p)| format!("(\"{}\", BlsUtils.traceMVQ {} {})", e, e, p))
        .collect();

        let all_traces = [constants_tracing, scalar_traces, mvq_traces];
        let all_traces: Vec<_> = all_traces.iter().flatten().collect();

        data.insert("TRACES".to_string(), all_traces.iter().join(",\n       "));
    }

    #[cfg(not(feature = "plutus_debug"))]
    data.insert("TRACES".to_string(), "".to_string());

    let mut handlebars = Handlebars::new();
    handlebars.set_strict_mode(true);
    handlebars.register_template_file("haskell_template", template_file)?;
    let mut output_file = File::create(haskell_file)?;
    handlebars.render_to_write("haskell_template", &data, &mut output_file)?;
    handlebars.render("haskell_template", &data)
}

pub fn emit_vk_code(
    template_file: &Path, // haskell mustashe template
    haskell_file: &Path,  // generated haskell file, output
    circuit: &CircuitRepresentation,
) -> Result<String, RenderError> {
    let mut data: HashMap<String, String> = HashMap::new(); // data to bind to mustache template

    let points = circuit
        .instantiation_data
        .fixed_commitments
        .clone()
        .iter()
        .map(|a| {
            format!(
                "    (0x{}, 0x{})",
                hex::encode(a.x().to_bytes_be()),
                hex::encode(a.y().to_bytes_be())
            )
        })
        .join(",\n");
    let exports = (1..=circuit.instantiation_data.fixed_commitments.len())
        .map(|id| format!("  f{}_commitment,\n", id))
        .join("");
    let assignment = circuit.instantiation_data.fixed_commitments.clone().iter().enumerate().map(|(id, point)| {
        if point.is_identity().into() {
            format!("f{}_commitment :: BuiltinBLS12_381_G1_Element\nf{}_commitment = (bls12_381_G1_uncompress bls12_381_G1_compressed_zero)\n", id + 1, id + 1)
        } else {
            format!("f{}_commitment :: BuiltinBLS12_381_G1_Element\nf{}_commitment = f_commitments !! {}\n", id + 1, id + 1, id)
        }
    }).join("");

    data.insert("FIXED_COMMITMENTS".to_string(), points);
    data.insert("FIXED_COMMITMENTS_EXPORTS".to_string(), exports);
    data.insert("FIXED_COMMITMENT_G1".to_string(), assignment);

    let points = circuit
        .instantiation_data
        .permutation_commitments
        .clone()
        .iter()
        .map(|a| {
            format!(
                "    (0x{}, 0x{})",
                hex::encode(a.x().to_bytes_be()),
                hex::encode(a.y().to_bytes_be())
            )
        })
        .join(",\n");
    let exports = (1..=circuit.instantiation_data.permutation_commitments.len())
        .map(|id| format!("  p{}_commitment,\n", id))
        .join("");
    let assignment = circuit.instantiation_data.permutation_commitments.clone().iter().enumerate().map(|(id, point)| {
        if point.is_identity().into() {
            format!("p{}_commitment :: BuiltinBLS12_381_G1_Element\np{}_commitment = (bls12_381_G1_uncompress bls12_381_G1_compressed_zero)\n", id + 1, id + 1)
        } else {
            format!("p{}_commitment :: BuiltinBLS12_381_G1_Element\np{}_commitment = p_commitments !! {}\n", id + 1, id + 1, id)
        }
    }).join("");

    data.insert("PERMUTATION_COMMITMENTS".to_string(), points);
    data.insert("PERMUTATION_COMMITMENTS_EXPORTS".to_string(), exports);
    data.insert("PERMUTATION_COMMITMENT_G1".to_string(), assignment);
    let compressed_sg2 = hex::encode(circuit.instantiation_data.s_g2.to_bytes());

    debug!("compressed_sg2: {}", compressed_sg2);

    data.insert(
        "G2_DEFINITIONS".to_string(),
        format!("\"{}\"", compressed_sg2),
    );
    data.insert(
        "OMEGA".to_string(),
        hex::encode(circuit.instantiation_data.omega.to_bytes_be()),
    );
    data.insert(
        "OMEGA_INV".to_string(),
        hex::encode(circuit.instantiation_data.inverted_omega.to_bytes_be()),
    );
    data.insert(
        "BARYCENTRIC_WEIGHT".to_string(),
        hex::encode(circuit.instantiation_data.barycentric_weight.to_bytes_be()),
    );
    data.insert(
        "TRANSCRIPT_REP".to_string(),
        hex::encode(
            circuit
                .instantiation_data
                .transcript_representation
                .to_bytes_be(),
        ),
    );
    data.insert(
        "BLINDING_FACTORS".to_string(),
        circuit.instantiation_data.blinding_factors.to_string(),
    );

    let mut handlebars = Handlebars::new();
    handlebars.set_strict_mode(true);
    handlebars.register_template_file("haskell_template", template_file)?;
    let mut output_file = File::create(haskell_file)?;
    handlebars.render_to_write("haskell_template", &data, &mut output_file)?;
    handlebars.render("haskell_template", &data)
}
