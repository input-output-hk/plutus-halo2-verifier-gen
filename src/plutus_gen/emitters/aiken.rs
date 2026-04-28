//! High level code for generating Halo2 verifier in Aiken
//! PCS related code is in `pcs` module directly.

use crate::plutus_gen::extraction::data::languages::aiken::*;
use crate::plutus_gen::extraction::data::{
    CircuitRepresentation, CommitmentData, ProofExtractionSteps, RotationDescription, constants::*,
};
use crate::plutus_gen::extraction::pcs::{ExtractPCS, PCSType};

use midnight_curves::{BlsScalar as Scalar, G1Projective};

use ff::Field;
use group::{Curve, Group, GroupEncoding};
use handlebars::{Handlebars, RenderError};
use itertools::Itertools;
use std::ops::Neg;
use std::{collections::HashMap, fs::File, iter::once, path::Path};

pub fn emit_verifier_code<PCS>(
    template_file: &Path, // aiken mustashe template
    aiken_file: &Path,    // generated aiken file, output
    profiler_file: Option<&Path>,
    circuit: &CircuitRepresentation<PCS>,
    test_data: Option<(Vec<u8>, Vec<u8>, Vec<Scalar>, Option<G1Projective>)>,
) -> Result<String, RenderError>
where
    PCS: ExtractPCS,
{
    // Data structure we write the code in and bind with mustache template
    let mut data: HashMap<String, String> = HashMap::new();

    let nb_public_inputs = circuit.proof_instantiation_data.public_inputs_count;
    let nb_committed_instances = circuit.proof_instantiation_data.committed_instances_count;
    let committed_instances_supported = circuit
        .proof_instantiation_data
        .committed_instances_supported;

    // Handling committed instances
    let (ci_names, absorb_cis) = if committed_instances_supported && nb_committed_instances > 0 {
        let ci_names = format!("ci_1: ByteArray") + if nb_public_inputs > 0 { ", " } else { "" };
        let absorb_cis = format!("    let transcript = common_g1(ci_1, transcript)\n");
        (ci_names, absorb_cis)
    } else {
        (String::new(), String::new())
    };
    data.insert("COMMITTED_INSTANCES_NAMES".to_string(), ci_names);
    data.insert("ABSORB_COMMITTED_INSTANCES".to_string(), absorb_cis);

    // Handling public inputs
    {
        let public_inputs_names: Vec<String> =
            (1..=nb_public_inputs).map(|n| format!("i_{}", n)).collect();

        // Writing public input names in verify function's interface
        data.insert(
            "PUBLIC_INPUTS_NAMES".to_string(),
            public_inputs_names
                .iter()
                .map(|name| format!("{} : State<Scalar>", name))
                .join(", "),
        );

        // Absorbing number and values of public inputs in transcript
        let nb_public_inputs = format!(
            "    let inputs_count = from_int({})\n",
            nb_public_inputs.to_string()
        );
        let number_in_transcript =
            format!("    let transcript = common_scalar(inputs_count, transcript)\n");

        let public_inputs = public_inputs_names
            .iter()
            .map(|name| format!("    let transcript = common_scalar({}, transcript)\n", name))
            .join("");

        let mut all_is = String::with_capacity(
            nb_public_inputs.len() + number_in_transcript.len() + public_inputs.len(),
        );
        all_is.push_str(&nb_public_inputs);
        all_is.push_str(&number_in_transcript);
        all_is.push_str(&public_inputs);
        data.insert("ABSORB_PUBLIC_INPUTS".to_string(), all_is);
    };

    // Extracting from transcript commitments and evaluations
    // Also generating instance's evaluation
    let public_inputs_lagrange = (1..=nb_public_inputs)
        .map(|n| format!("i_{}", n))
        .join(", ");

    let letters = 'a'..='z';
    let proof_extraction: Vec<_> = circuit
        .proof_extraction_steps
        .iter()
        .chunk_by(|e| (*e).clone())
        .into_iter()
        .map(|(section_type, section)| match section_type {
            ProofExtractionSteps::AdviceCommitments => section
                .enumerate()
                .map(|(number, _advice)| format!("    let (a{}, transcript) = read_point(transcript)\n", number + 1))
                .join(""),
            ProofExtractionSteps::Theta => "    let (theta, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::Beta => "    let (beta, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::Gamma => "    let (gamma, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::PermutationsCommitted => section
                .zip(letters.clone())
                .map(|(_permutation, letter)| {
                    format!("    let (permutations_committed_{}, transcript) = read_point(transcript)\n", letter)
                })
                .join(""),
            ProofExtractionSteps::VanishingRand => "    let (vanishing_rand, transcript) = read_point(transcript)\n".to_string(),
            ProofExtractionSteps::YCoordinate => "    let (y, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::VanishingSplit => section
                .enumerate()
                .map(|(number, _vanishing_split)| {
                    format!(
                        "\tlet (vanishing_split_{idx}, transcript) =  read_point(transcript)\n\
                        \tlet vanishing_split_{idx} = decompress(vanishing_split_{idx})\n",
                        idx = number + 1)
                })
                .join(""),
            ProofExtractionSteps::XCoordinate => {
                let squeezing_x = "    let (x, transcript) = squeeze_challenge(transcript)\n".to_string();
                let scaling_x = format!("    let xn_minus_one = scale(x, {}-1)\n",circuit.proof_instantiation_data.n_coefficient.to_string()).to_string();
                let scaling_x_again = "    let xn = mul(xn_minus_one, x)\n".to_string();
                let mut to_write_down = String::with_capacity(squeezing_x.len() +  scaling_x.len() + scaling_x_again.len());
                to_write_down.push_str(&squeezing_x);
                to_write_down.push_str(&scaling_x);
                to_write_down.push_str(&scaling_x_again);
                to_write_down
            },
            ProofExtractionSteps::AdviceEval => section
                .enumerate()
                .map(|(number, _advice_eval)| {
                    format!("    let (advice_eval_{}, transcript) = read_scalar(transcript)\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::FixedEval => section
                .enumerate()
                .map(|(number, _fixed_eval)| {
                    format!("    let (fixed_eval_{}, transcript) = read_scalar(transcript)\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::RandomEval => "    let (random_eval, transcript) = read_scalar(transcript)\n".to_string(),
            ProofExtractionSteps::PermutationCommon => section
                .enumerate()
                .map(|(number, _permutation_common)| {
                    format!("    let (permutation_common_{}, transcript) = read_scalar(transcript)\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::PermutationEval(letter) => section
                .enumerate()
                .map(|(n, _)| {
                    format!(
                        "    let ({}, transcript) = read_scalar(transcript)\n",
                        perm_eval_str(&letter,
                        n + 1)
                    )
                })
                .join(""),
            ProofExtractionSteps::SqueezeChallenge => panic!("no Squeeze Challenge supported"),
            ProofExtractionSteps::LookupPermuted => section
                .enumerate()
                .map(|(number, _lookup_permuted)| {
                    format!("    let (permuted_input_{}, transcript) =  read_point(transcript)\n", number + 1)
                        + &format!("    let (permuted_table_{}, transcript) =  read_point(transcript)\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::LookupCommitment => section
                .enumerate()
                .map(|(number, _lookup_commitment)| {
                    format!("    let (lookup_commitment_{}, transcript) =  read_point(transcript)\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::LookupEval => section
                .enumerate()
                .map(|(number, _permutation_common)| {
                    format!("    let (product_eval_{}, transcript) = read_scalar(transcript)\n", number + 1)
                        + &format!("    let (product_next_eval_{}, transcript) = read_scalar(transcript)\n", number + 1)
                        + &format!("    let (permuted_input_eval_{}, transcript) = read_scalar(transcript)\n", number + 1)
                        + &format!(
                        "    let (permuted_input_inv_eval_{}, transcript) = read_scalar(transcript)\n",
                        number + 1
                    )
                        + &format!("    let (permuted_table_eval_{}, transcript) = read_scalar(transcript)\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::Trash => "    let (trash, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::TrashCommitment => section.enumerate().map(|(number, _trashcan)| {
                format!("    let (trashcan_commitment_{}, transcript) =  read_point(transcript)\n", number + 1)
            }).join(""),
            ProofExtractionSteps::TrashEval => section.enumerate().map(|(number, _trashcan)| {
                format!("    let (trashcan_eval_{}, transcript) = read_scalar(transcript)\n", number + 1)
            }).join(""),
            ProofExtractionSteps::CommittedInstanceEval => section.enumerate().map(|(number, _ci)| {
                match (committed_instances_supported,nb_committed_instances) {
                    (false, _) => panic!("This case should never happen, as we should not have any CommittedInstanceEval"),
                    (true, 0) => {assert!(number == 0); format!("\n    let instance_eval_1 = from_int(0)\n")},
                    (true, _) => format!("    let (instance_eval_{}, transcript) = read_scalar(transcript)\n", number + 1)
                }
            }).join(""),
            ProofExtractionSteps::InstanceEval => section.enumerate().map(|(number, _i)| {
                let offset = nb_committed_instances;
                if nb_public_inputs == 0 {
                    format!("    let instance_eval_{} = from_int(0)\n", number + offset + 1)
                } else {
                let rotations = format!("\n    let rotations_for_instances = rotate_omegas(omega, omega_inv, 0, {})\n", nb_public_inputs);
                let lagrange = format!("    let lagrange_polynomial_instances = lagrange_polynomial_basis( x, xn, barycentric_weight, rotations_for_instances)\n");
                let instance = format!("    let instance_eval_{} = inner_product(lagrange_polynomial_instances, [{}])\n\n", number + offset + 1, public_inputs_lagrange);
                let mut all_strings_instance = String::with_capacity(
                    rotations.len() + lagrange.len() + instance.len(),
                );
                all_strings_instance.push_str(&rotations);
                all_strings_instance.push_str(&lagrange);
                all_strings_instance.push_str(&instance);
                all_strings_instance
            }
            }).join("")
            ,
        })
        .collect();

    let pcs_extraction = circuit
        .pcs_extraction_steps
        .iter()
        .chunk_by(|e| (*e).clone())
        .into_iter()
        .map(|(section_type, section)| {
            section
                .enumerate()
                .map(|(number, _step)| PCS::step_to_aiken(section_type.clone(), number + 1))
                .join("")
        })
        .collect::<Vec<_>>();

    let extraction_stage = proof_extraction.join("") + &pcs_extraction.join("");
    data.insert("PES".to_string(), extraction_stage);

    // Adding expressions for gates, lookups, permutations and trashcans
    {
        // Adding gate expressions
        // For gates, the selector is already included in the constraint/expression
        let gates = circuit
            .expressions
            .compiled_gate_equations
            .iter()
            .enumerate()
            .map(|(id, gate)| {
                format!(
                    "    let gate_eq{:?} = {}\n",
                    id + 1,
                    gate.compile_expression()
                )
            })
            .join("");
        data.insert("GATES".to_string(), gates);

        // Adding lookup table expressions
        let lookup_tables = circuit
            .expressions
            .compiled_lookups_equations
            .1
            .iter()
            .enumerate()
            .map(|(id, gate)| {
                format!(
                    "    let lookup_table_eq{:?} = {}\n",
                    id + 1,
                    combine_aiken_expressions(gate.clone(), THETA_STR)
                )
            })
            .join("");
        data.insert("LOOKUP_TABLES_EXPRESSIONS".to_string(), lookup_tables);

        // Adding lookup input expressions
        let lookup_inputs = circuit
            .expressions
            .compiled_lookups_equations
            .0
            .iter()
            .enumerate()
            .map(|(id, gate)| {
                format!(
                    "    let lookup_input_eq{:?} = {}\n",
                    id + 1,
                    combine_aiken_expressions(gate.clone(), THETA_STR)
                )
            })
            .join("");
        data.insert("LOOKUP_INPUTS_EXPRESSIONS".to_string(), lookup_inputs);

        // Combining lookup expressions
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

            let l1 = format!("mul({}, sub({}, product_eval_{}))", EVAL_0_STR, ONE_STR, id);
            let l2 = format!("mul({}, sub(mul(product_eval_{}, product_eval_{}), product_eval_{}))", EVAL_LAST_STR, id, id, id);
            let left = format!("mul(mul(product_next_eval_{}, add(permuted_input_eval_{}, beta)), add(permuted_table_eval_{}, gamma))", id, id, id);
            let right = format!("mul(mul(product_eval_{}, add(lookup_input_eq{}, beta)), add(lookup_table_eq{}, gamma))", id, id, id);
            let l3 = format!("mul(sub(lookup_left_{}, lookup_right_{}), active_rows)", id, id);
            let l4 = format!("mul({}, sub(permuted_input_eval_{}, permuted_table_eval_{}))", EVAL_0_STR, id, id);
            let l5 = format!("mul(mul(sub(permuted_input_eval_{}, permuted_table_eval_{}), sub(permuted_input_eval_{}, permuted_input_inv_eval_{})), active_rows)", id, id, id, id);

            format!("    let lookup_expression_1_{} = {}\n", id, l1) +
                format!("    let lookup_expression_2_{} = {}\n", id, l2).as_str() +
                format!("    let lookup_left_{} = {}\n", id, left).as_str() +
                format!("    let lookup_right_{} = {}\n", id, right).as_str() +
                format!("    let lookup_expression_3_{} = {}\n", id, l3).as_str() +
                format!("    let lookup_expression_4_{} = {}\n", id, l4).as_str() +
                format!("    let lookup_expression_5_{} = {}\n\n\n", id, l5).as_str()
        })
        .join("");

        data.insert("LOOKUPS".to_string(), lookup_equations);

        // Adding permutation evaluation expressions
        let permutation_evals = circuit
            .expressions
            .permutations_evaluated_terms
            .iter()
            .enumerate()
            .map(|(id, expression)| {
                let term = expression.compile_expression();
                format!("    let term_{:?} = {}\n", id + 1, term)
            })
            .join("");
        data.insert("PERMUTATIONS_EVALS".to_string(), permutation_evals);

        let mut sets_lhs: HashMap<char, String> = HashMap::new();
        let mut sets_rhs: HashMap<char, String> = HashMap::new();

        // Adding left permutation expressions
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
                    sets_lhs.insert(*set, format!("mul({}, left{:?})", existing, id + 1));
                } else {
                    sets_lhs.insert(*set, format!("left{:?}", id + 1));
                };
                let term = expression.compile_expression();
                format!(
                    "    let left{:?} = {} //part of set {}\n",
                    id + 1,
                    term,
                    set
                )
            })
            .join("");
        data.insert("PERMUTATIONS_LHS".to_string(), permutation_lhs);

        // Combining left permutation expressions
        let lhf_sets = sets_lhs
            .iter()
            .sorted_by_key(|(c, _)| **c)
            .enumerate()
            .map(|(set_number, (set_id, terms))| {
                format!(
                    "    let left_set{:?} = mul({}, {}) \n",
                    set_number + 1,
                    perm_eval_str(set_id, 2),
                    terms
                )
            })
            .join("");
        data.insert("LHS_SETS".to_string(), lhf_sets);

        // Adding right permutation expressions
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
                    sets_rhs.insert(*set, format!("mul({}, right{:?})", existing, id + 1));
                } else {
                    sets_rhs.insert(*set, format!("right{:?}", id + 1));
                };
                let term = expression.compile_expression();
                format!(
                    "    let right{:?} = {} //part of set {}\n",
                    id + 1,
                    term,
                    set
                )
            })
            .join("");
        data.insert("PERMUTATIONS_RHS".to_string(), permutation_rhs);

        // Combining right permutation expressions
        let rhf_sets = sets_rhs
            .iter()
            .sorted_by_key(|(c, _)| **c)
            .enumerate()
            .map(|(set_number, (set_id, terms))| {
                format!(
                    "    let right_set{:?} = mul({}, {}) \n",
                    set_number + 1,
                    perm_eval_str(set_id, 1),
                    terms
                )
            })
            .join("");
        data.insert("RHS_SETS".to_string(), rhf_sets);

        // Combining left and right permutation expressions
        let permutations_combined = if sets_lhs.len() == sets_rhs.len() {
            let sets_number = sets_lhs.len();
            (1..=sets_number).map(|n| {
            format!("    let permutations{} = mul(sub(left_set{}, right_set{}), sub({}, add({}, sum_of_evaluation_for_blinding_factors)))\n", n, n, n, ONE_STR, EVAL_LAST_STR)
        }).join("")
        } else {
            panic!("permutations sets have to be equal length")
        };
        data.insert("PERMUTATIONS_COMBINED".to_string(), permutations_combined);

        // Adding trashcan expressions
        let trashcans = circuit
            .expressions
            .compiled_trashcans
            .iter()
            .enumerate()
            .map(|(id, trash_info)| {
                let (_name, selector, expression) = trash_info;
                format!(
                    "    let trashcan_exp{:?} = sub({}, mul(sub({}, {}), trashcan_eval_{:?}))\n",
                    id + 1,
                    combine_aiken_expressions(expression.clone(), TRASH_STR),
                    ONE_STR,
                    selector.compile_expression(),
                    id + 1
                )
            })
            .join("");
        data.insert("TRASHCANS".to_string(), trashcans);

        // Computing vanishing expressions by relisting all gates and step expressions
        let gates_count = circuit.expressions.compiled_gate_equations.len();
        let permutations_eval_count = circuit.expressions.permutations_evaluated_terms.len();
        let sets_count = sets_lhs.len();
        let lookups_count = circuit.expressions.compiled_lookups_equations.0.len();
        let trashcans_count = circuit.expressions.compiled_trashcans.len();

        let mut total_nb_expressions = 0;

        // Adding gate expressions to vanishing
        let mut vanishing_expressions = (1..=gates_count)
            .map(|n| format!("    let expression{} = gate_eq{}\n", n, n))
            .collect::<Vec<_>>();
        total_nb_expressions += gates_count;

        // Adding permutation evaluation expressions to vanishing
        let expressions = (1..=permutations_eval_count)
            .map(|n| {
                format!(
                    "    let expression{} = term_{}\n",
                    n + total_nb_expressions,
                    n
                )
            })
            .collect::<Vec<_>>();
        total_nb_expressions += permutations_eval_count;
        vanishing_expressions.extend(expressions);

        // Adding combined permutations expressions to vanishing
        let expressions = (1..=sets_count)
            .map(|n| {
                format!(
                    "    let expression{} = permutations{}\n",
                    n + total_nb_expressions,
                    n
                )
            })
            .collect::<Vec<_>>();
        total_nb_expressions += sets_count;
        vanishing_expressions.extend(expressions);

        // Adding lookup expressions to vanishing
        let expressions = (1..=lookups_count)
            .flat_map(|n| {
                [
                    format!(
                        "    let expression{} = lookup_expression_1_{}\n",
                        ((n - 1) * 5) + 1 + total_nb_expressions,
                        n
                    ),
                    format!(
                        "    let expression{} = lookup_expression_2_{}\n",
                        ((n - 1) * 5) + 2 + total_nb_expressions,
                        n
                    ),
                    format!(
                        "    let expression{} = lookup_expression_3_{}\n",
                        ((n - 1) * 5) + 3 + total_nb_expressions,
                        n
                    ),
                    format!(
                        "    let expression{} = lookup_expression_4_{}\n",
                        ((n - 1) * 5) + 4 + total_nb_expressions,
                        n
                    ),
                    format!(
                        "    let expression{} = lookup_expression_5_{}\n",
                        ((n - 1) * 5) + 5 + total_nb_expressions,
                        n
                    ),
                ]
            })
            .collect::<Vec<_>>();
        total_nb_expressions += lookups_count * 5;
        vanishing_expressions.extend(expressions);

        // Adding trashcan expressions to vanishing
        let expressions = (1..=trashcans_count)
            .map(|n| {
                format!(
                    "    let expression{} = trashcan_exp{}\n",
                    n + total_nb_expressions,
                    n
                )
            })
            .collect::<Vec<_>>();
        total_nb_expressions += trashcans_count;
        vanishing_expressions.extend(expressions);

        data.insert(
            "VANISHING_EXPRESSIONS".to_string(),
            vanishing_expressions.join(""),
        );

        // Adding vanishing evaluations
        let mut vanishing_evaluation = format!("add(mul({}, y), expression1)", ZERO_STR);
        for n in 2..=total_nb_expressions {
            vanishing_evaluation = format!("add(mul({}, y), expression{})", vanishing_evaluation, n)
        }
        let vanishing_evaluation = format!("    let hEval = {}\n", vanishing_evaluation);
        data.insert("VANISHING_EVALUATION".to_string(), vanishing_evaluation);

        // Adding vanishing_g and h_commitments expressions
        let h_commitments = circuit
            .expressions
            .h_commitments
            .iter()
            .map(|(variable_name, expression)| {
                let term = expression.compile_expression();
                format!("    let {} = {}\n", variable_name, term)
            })
            .join("");
        data.insert("H_COMMITMENTS".to_string(), h_commitments);
    }

    let (unique_grouped_points, commitment_data) = PCS::precompute_intermediate_sets(&circuit);

    // Adding PCS related data and commitments.
    if PCS::pcs_type() == PCSType::Halo2MultiOpen {
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
            "HALO2_X1_POWERS_COUNT".to_string(),
            max_commitments_per_points_set.to_string(),
        );

        data.insert(
            "HALO2_X4_POWERS_COUNT".to_string(),
            (point_sets_indexes.len() + 1).to_string(),
        );

        let q_evaluations = PCS::pcs_data_plinth(&circuit);
        data.insert("HALO2_Q_EVALS_FROM_PROOF".to_string(), q_evaluations);

        // Pre-sort commitment data by point set index to save on this inside the contract
        let halo2_commitment_data = point_sets_indexes
            .iter()
            .map(|idx| {
                let commitments_in_set: Vec<&CommitmentData> = commitment_data
                    .iter()
                    .filter(|&cd| cd.point_set_index == *idx)
                    .collect();

                let commitments_in_set_str = commitments_in_set
                    .iter()
                    .map(|commitment_data| {
                        format!(
                            "\t\t\t({}, [{}])",
                            commitment_data.commitment.compile_expression(),
                            commitment_data
                                .evaluations
                                .iter()
                                .map(AikenExpression::compile_expression)
                                .join(",")
                        )
                    })
                    .join(",\n");

                format!("\n\t\t[\n{}\n\t\t]", commitments_in_set_str)
            })
            .join(",");

        let kzg_halo2_commitment_map =
            format!("\tlet commitment_data = [{}]", halo2_commitment_data);
        data.insert("HALO2_COMMITMENT_MAP".to_string(), kzg_halo2_commitment_map);

        let kzg_halo2_point_sets = unique_grouped_points
            .iter()
            .map(|set| set.iter().map(RotationDescription::to_string).join(","))
            .join("],[");

        let kzg_halo2_point_sets = format!("     let point_sets = [[{}]]", kzg_halo2_point_sets);
        data.insert("HALO2_POINT_SETS".to_string(), kzg_halo2_point_sets);
    }

    let fixed_commitments_imports = (1..=circuit.proof_instantiation_data.fixed_commitments.len())
        .map(|id| format!("f{}_commitment", id))
        .join(", ");
    let permutation_commitments_imports = (1..=circuit
        .proof_instantiation_data
        .permutation_commitments
        .len())
        .map(|id| format!("p{}_commitment", id))
        .join(", ");

    data.insert("F_IMPORTS".to_string(), fixed_commitments_imports);
    data.insert("P_IMPORTS".to_string(), permutation_commitments_imports);

    // Adding test data
    match test_data {
        None => {
            data.insert(
                "TEST_VALID_PROOF_VALID_INPUTS".to_string(),
                "True".to_string(),
            );
            data.insert(
                "TEST_VALID_PROOF_INVALID_INPUTS".to_string(),
                "False".to_string(),
            );
            data.insert(
                "TEST_INVALID_PROOF_INVALID_INPUTS".to_string(),
                "False".to_string(),
            );
            data.insert(
                "TEST_VALID_PROOF_TRIVIAL_INPUTS".to_string(),
                "False".to_string(),
            );
            data.insert(
                "TEST_TRIVIAL_PROOF_TRIVIAL_INPUTS".to_string(),
                "False".to_string(),
            );
        }
        Some((proof, invalid_proof, public_inputs, committed_instances_opt)) => {
            let valid_pi = public_inputs
                .iter()
                .map(|e| format!("from_int(0x{})", hex::encode(e.to_bytes_be())))
                .join(", ");

            let invalid_pi = public_inputs
                .iter()
                .map(|e| {
                    let invalid_input = e.neg();
                    format!("from_int(0x{})", hex::encode(invalid_input.to_bytes_be()))
                })
                .join(", ");

            let trivial_pi = public_inputs
                .iter()
                .map(|_e| format!("from_int(0x{})", hex::encode(Scalar::ONE.to_bytes_be())))
                .join(", ");

            let committed_inputs = committed_instances_opt.map_or("".to_string(), |p| {
                format!("#\"{}\"", hex::encode(p.to_affine().to_bytes())).to_string()
            });

            let invalid_committed_inputs = committed_instances_opt.map_or("".to_string(), |p| {
                format!(
                    "#\"{}\"",
                    hex::encode((G1Projective::generator() + p).to_affine().to_bytes())
                )
                .to_string()
            });

            let trivial_committed_inputs = committed_instances_opt.map_or("".to_string(), |_| {
                format!(
                    "#\"{}\"",
                    hex::encode((G1Projective::generator()).to_affine().to_bytes())
                )
                .to_string()
            });

            let valid_inputs = [committed_inputs.clone(), valid_pi]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", ");

            let invalid_inputs = [invalid_committed_inputs.clone(), invalid_pi]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", ");

            let trivial_inputs = [trivial_committed_inputs, trivial_pi]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", ");

            let test_valid_proof_valid_inputs = format!(
                "verifier(#\"{}\", {})",
                hex::encode(proof.clone()),
                valid_inputs
            );

            data.insert(
                "TEST_VALID_PROOF_VALID_INPUTS".to_string(),
                test_valid_proof_valid_inputs,
            );

            if let Some(template) = profiler_file {
                let mut handlebars = Handlebars::new();
                handlebars.set_strict_mode(true);
                handlebars.register_template_file("profiler_template", template)?;
                let mut output_file =
                    File::create("aiken-verifier/aiken_halo2/validators/profiler.ak")?;
                handlebars.render_to_write("profiler_template", &data, &mut output_file)?;
                handlebars.render("profiler_template", &data)?;
            }

            let test_valid_proof_invalid_inputs = format!(
                "verifier(#\"{}\", {})",
                hex::encode(proof.clone()),
                invalid_inputs
            );

            data.insert(
                "TEST_VALID_PROOF_INVALID_INPUTS".to_string(),
                test_valid_proof_invalid_inputs,
            );

            let test_invalid_proof_invalid_inputs = format!(
                "verifier(#\"{}\", {})",
                hex::encode(invalid_proof),
                invalid_inputs
            );

            data.insert(
                "TEST_INVALID_PROOF_INVALID_INPUTS".to_string(),
                test_invalid_proof_invalid_inputs,
            );

            let test_valid_proof_trivial_inputs = format!(
                "verifier(#\"{}\", {})",
                hex::encode(proof.clone()),
                trivial_inputs
            );
            data.insert(
                "TEST_VALID_PROOF_TRIVIAL_INPUTS".to_string(),
                test_valid_proof_trivial_inputs,
            );
        }
    }

    let mut handlebars = Handlebars::new();
    handlebars.set_strict_mode(true);
    handlebars.register_template_file("aiken_template", template_file)?;
    let mut output_file = File::create(aiken_file)?;
    handlebars.render_to_write("aiken_template", &data, &mut output_file)?;
    handlebars.render("aiken_template", &data)
}

pub fn emit_vk_code<PCS>(
    template_file: &Path,
    aiken_file: &Path,
    circuit: &CircuitRepresentation<PCS>,
) -> Result<String, RenderError>
where
    PCS: ExtractPCS,
{
    let mut data: HashMap<String, String> = HashMap::new(); // data to bind to mustache template

    let points = circuit
        .proof_instantiation_data
        .fixed_commitments
        .iter()
        .cloned()
        .map(|g| hex::encode(g.to_bytes()));

    let points = points
        .enumerate()
        .map(|(idx, g1_encoded)| {
            format!(
                "pub const f{}_commitment: ByteArray = #\"{}\"",
                idx + 1,
                g1_encoded
            )
        })
        .join("\n");

    data.insert("FIXED_COMMITMENTS".to_string(), points);

    let points = circuit
        .proof_instantiation_data
        .permutation_commitments
        .iter()
        .cloned()
        .map(|g| hex::encode(g.to_bytes()));

    let points = points
        .enumerate()
        .map(|(idx, g1_encoded)| {
            format!(
                "pub const p{}_commitment: ByteArray = #\"{}\"",
                idx + 1,
                g1_encoded
            )
        })
        .join("\n");

    data.insert("PERMUTATION_COMMITMENTS".to_string(), points);

    let compressed_sg2 = hex::encode(circuit.proof_instantiation_data.s_g2.to_bytes());

    data.insert(
        "G2_DEFINITIONS".to_string(),
        format!("\"{}\"", compressed_sg2),
    );
    data.insert(
        "OMEGA".to_string(),
        hex::encode(circuit.proof_instantiation_data.omega.to_bytes_be()),
    );
    data.insert(
        "OMEGA_INV".to_string(),
        hex::encode(
            circuit
                .proof_instantiation_data
                .inverted_omega
                .to_bytes_be(),
        ),
    );
    data.insert(
        "BARYCENTRIC_WEIGHT".to_string(),
        hex::encode(
            circuit
                .proof_instantiation_data
                .barycentric_weight
                .to_bytes_be(),
        ),
    );
    data.insert(
        "TRANSCRIPT_REP".to_string(),
        hex::encode(
            circuit
                .proof_instantiation_data
                .transcript_representation
                .to_bytes_be(),
        ),
    );
    data.insert(
        "BLINDING_FACTORS".to_string(),
        circuit
            .proof_instantiation_data
            .blinding_factors
            .to_string(),
    );

    let fixed_commitments = circuit.proof_instantiation_data.fixed_commitments.len();

    let permutation_commitments = circuit
        .proof_instantiation_data
        .permutation_commitments
        .len();

    let fixed = (1..=fixed_commitments).map(|idx| {
        format!(
            "\tlet f{idx}_commitment = decompress(f{idx}_commitment)\n\
            \texpect f{idx}_commitment == f{idx}_commitment"
        )
    });
    let permutations = (1..=permutation_commitments).map(|idx| {
        format!(
            "\tlet p{idx}_commitment = decompress(p{idx}_commitment)\n\
            \texpect p{idx}_commitment == p{idx}_commitment"
        )
    });

    let budget_check = fixed
        .chain(permutations)
        .chain(once("    expect g2_const == g2_const".to_string()))
        .join("\n");

    data.insert("BUDGET_CHECK".to_string(), budget_check);

    let mut handlebars = Handlebars::new();
    handlebars.set_strict_mode(true);
    handlebars.register_template_file("aiken_template", template_file)?;
    let mut output_file = File::create(aiken_file)?;
    handlebars.render_to_write("aiken_template", &data, &mut output_file)?;
    handlebars.render("aiken_template", &data)
}
