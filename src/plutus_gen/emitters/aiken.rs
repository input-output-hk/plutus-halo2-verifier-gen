//! High level code for generating Halo2 verifier in Aiken
//! PCS related code is in `pcs` module directly.

use crate::plutus_gen::extraction::data::languages::aiken::*;
use crate::plutus_gen::extraction::data::{
    CircuitRepresentation, CommitmentData, Commitments, Evaluations, ProofExtractionSteps, Query,
    RotationDescription, constants::*,
};
use crate::plutus_gen::extraction::pcs::{ExtractPCS, PCSType};

use midnight_curves::BlsScalar as Scalar;

use ff::Field;
use group::GroupEncoding;
use handlebars::{Handlebars, RenderError};
use itertools::Itertools;
use std::ops::Neg;
use std::{collections::HashMap, fs::File, iter::once, path::Path};

pub fn emit_verifier_code<PCS>(
    template_file: &Path, // aiken mustashe template
    aiken_file: &Path,    // generated aiken file, output
    profiler_file: Option<&Path>,
    circuit: &CircuitRepresentation<PCS>,
    test_data: Option<(Vec<u8>, Vec<u8>, Vec<Scalar>)>,
) -> Result<String, RenderError>
where
    PCS: ExtractPCS,
{
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
            ProofExtractionSteps::XCoordinate => "    let (x, transcript) = squeeze_challenge(transcript)\n".to_string(),
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
            ProofExtractionSteps::Trash => "    let (trash_challenge, transcript) = squeeze_challenge(transcript)\n".to_string(),
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

    let mut data: HashMap<String, String> = HashMap::new(); // data to bind to mustache template

    data.insert(
        "PUBLIC_INPUTS_COUNT".to_string(),
        circuit.public_inputs.to_string(),
    );

    let public_inputs_lagrange = (1..=circuit.proof_instantiation_data.public_inputs_count)
        .map(|n| format!("i_{}", n))
        .join(", ");
    data.insert("PUBLIC_INPUTS_LAGRANGE".to_string(), public_inputs_lagrange);

    let public_inputs = (1..=circuit.proof_instantiation_data.public_inputs_count)
        .map(|n| format!("    let transcript = common_scalar(i_{}, transcript)\n", n))
        .join("");

    data.insert("PUBLIC_INPUTS".to_string(), public_inputs);

    let public_inputs_names = (1..=circuit.proof_instantiation_data.public_inputs_count)
        .map(|n| format!("i_{}: State<Scalar>", n))
        .join(", ");

    data.insert("PUBLIC_INPUTS_NAMES".to_string(), public_inputs_names);

    let extraction_stage = proof_extraction.join("") + &pcs_extraction.join("");
    data.insert("PES".to_string(), extraction_stage);

    data.insert(
        "X_EXPONENT".to_string(),
        circuit.proof_instantiation_data.n_coefficient.to_string(),
    );

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
                combine_aiken_expressions(gate.clone())
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
                "    let lookup_input_eq{:?} = {}\n",
                id + 1,
                combine_aiken_expressions(gate.clone())
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

    let permutations_combined = if sets_lhs.len() == sets_rhs.len() {
        let sets_number = sets_lhs.len();
        (1..=sets_number).map(|n| {
            format!("    let permutations{} = mul(sub(left_set{}, right_set{}), sub({}, add({}, sum_of_evaluation_for_blinding_factors)))\n", n, n, n, ONE_STR, EVAL_LAST_STR)
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
        .map(|n| format!("    let expression{} = gate_eq{}\n", n, n))
        .collect::<Vec<_>>();
    total_nb_expressions += gates_count;

    let expressions = (1..=permutations_eval_count)
        .map(|n| {
            format!(
                "    let expression{} = term_{}\n",
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
                "    let expression{} = permutations{}\n",
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
    vanishing_expressions.extend(expressions);
    total_nb_expressions += lookups_count * 5;

    data.insert(
        "VANISHING_EXPRESSIONS".to_string(),
        vanishing_expressions.join(""),
    );

    let mut vanishing_evaluation = format!("add(mul({}, y), expression1)", ZERO_STR);
    for n in 2..=(total_nb_expressions) {
        vanishing_evaluation = format!("add(mul({}, y), expression{})", vanishing_evaluation, n)
    }
    let vanishing_evaluation = format!("    let hEval = {}\n", vanishing_evaluation);
    data.insert("VANISHING_EVALUATION".to_string(), vanishing_evaluation);

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

    let (unique_grouped_points, commitment_data) = PCS::precompute_intermediate_sets(&circuit);

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
        Some((proof, invalid_proof, public_inputs)) => {
            let test_valid_proof_valid_inputs = format!(
                "verifier(#\"{}\", {})",
                hex::encode(proof.clone()),
                public_inputs
                    .iter()
                    .map(|e| format!("from_int(0x{})", hex::encode(e.to_bytes_be())))
                    .join(", ")
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
                public_inputs
                    .iter()
                    .map(|e| {
                        let invalid_input = e.neg();
                        format!("from_int(0x{})", hex::encode(invalid_input.to_bytes_be()))
                    })
                    .join(", ")
            );

            data.insert(
                "TEST_VALID_PROOF_INVALID_INPUTS".to_string(),
                test_valid_proof_invalid_inputs,
            );

            let test_invalid_proof_invalid_inputs = format!(
                "verifier(#\"{}\", {})",
                hex::encode(invalid_proof),
                public_inputs
                    .iter()
                    .map(|e| {
                        let invalid_input = e.neg();
                        format!("from_int(0x{})", hex::encode(invalid_input.to_bytes_be()))
                    })
                    .join(", ")
            );

            data.insert(
                "TEST_INVALID_PROOF_INVALID_INPUTS".to_string(),
                test_invalid_proof_invalid_inputs,
            );

            let test_valid_proof_trivial_inputs = format!(
                "verifier(#\"{}\", {})",
                hex::encode(proof.clone()),
                public_inputs
                    .iter()
                    .map(|_e| format!("from_int(0x{})", hex::encode(Scalar::ONE.to_bytes_be())))
                    .join(", ")
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

#[derive(Clone, Eq, PartialEq, Debug)]
enum ScalarOperation {
    Zero,
    Mul(Box<ScalarOperation>, Evaluations),
    MulS(Box<ScalarOperation>, Box<ScalarOperation>),
    Power(char, i32),
    Add(Box<ScalarOperation>, Box<ScalarOperation>),
    Rotation(RotationDescription),
}

#[derive(Clone, Eq, PartialEq)]
enum MsmOperations {
    Empty,
    Append(Box<MsmOperations>, ScalarOperation, Commitments),
    AppendW(Box<MsmOperations>, ScalarOperation, usize),
    AppendNegatedG1(Box<MsmOperations>, ScalarOperation),
    Add(Box<MsmOperations>, Box<MsmOperations>),
    Scale(Box<MsmOperations>, ScalarOperation),
}

impl AikenExpression for OptimizedMSM {
    fn compile_expression(&self) -> String {
        let elements = self
            .elements
            .iter()
            .map(|element| match element {
                ElementMSM::Element(scalar, commitment) => format!(
                    "\n\t\t\t\tMSMElement {{ scalar: {}, g1: {} }}",
                    scalar.compile_expression(),
                    commitment.compile_expression(),
                ),
                ElementMSM::ElementW(scalar, index) => format!(
                    "\n\t\t\t\tMSMElement {{ scalar: {}, g1: w{} }}",
                    scalar.compile_expression(),
                    index + 1,
                ),
                ElementMSM::ElementNegatedG1(scalar) => {
                    format!(
                        "\n\t\t\t\tMSMElement {{ scalar: {}, g1: neg_g1_generator }}",
                        scalar.compile_expression(),
                    )
                }
            })
            .join(", ");
        format!("MSM{{elements: [ {} ]}}", elements)
    }
}

impl AikenExpression for ScalarOperation {
    fn compile_expression(&self) -> String {
        match self {
            //if rules are for eliminating operations that outcome can be predicted
            Self::Mul(scalar, evaluation) if matches!(**scalar, Self::Power(_, 0)) => {
                evaluation.compile_expression()
            }
            Self::MulS(scalar_a, scalar_b) if matches!(**scalar_a, Self::Power(_, 0)) => {
                scalar_b.compile_expression()
            }
            Self::MulS(scalar_a, scalar_b) if matches!(**scalar_b, Self::Power(_, 0)) => {
                scalar_a.compile_expression()
            }
            Self::Power(_name, exponent) if *exponent == 0 => ONE_STR.to_string(),
            Self::Add(scalar_a, scalar_b) if **scalar_a == Self::Zero => {
                scalar_b.compile_expression()
            }

            Self::Zero => ZERO_STR.to_string(),
            Self::Mul(scalar, evaluation) => {
                format!(
                    "mul({}, {})",
                    scalar.compile_expression(),
                    evaluation.compile_expression()
                )
            }
            Self::MulS(scalar_a, scalar_b) => {
                format!(
                    "mul({}, {})",
                    scalar_a.compile_expression(),
                    scalar_b.compile_expression()
                )
            }
            Self::Power(name, exponent) => {
                // All powers of `v` and `u` are pre-computed to avoid duplication
                // so here instead of calling `scale(v, X)` we just refer to `vX` variable
                // format!("scale({}, {})", name, exponent)
                format!("{}{}", name, exponent)
            }
            Self::Add(scalar_a, scalar_b) => {
                format!(
                    "add({}, {})",
                    scalar_a.compile_expression(),
                    scalar_b.compile_expression()
                )
            }
            Self::Rotation(x) => RotationDescription::to_string(x),
        }
    }
}
