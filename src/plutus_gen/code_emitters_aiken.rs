use crate::plutus_gen::decode_rotation;
use crate::plutus_gen::extraction::{
    AikenExpression, combine_aiken_expressions,
    data::{CircuitRepresentation, ProofExtractionSteps},
    precompute_intermediate_sets,
};
use blstrs::Scalar;
use ff::Field;
use halo2_proofs::halo2curves::group::GroupEncoding;
use handlebars::{Handlebars, RenderError};
use itertools::Itertools;
use log::debug;
use std::ops::Neg;
use std::{collections::HashMap, fs::File, iter::once, path::Path};

pub fn emit_verifier_code(
    template_file: &Path, // aiken mustashe template
    aiken_file: &Path,    // generated aiken file, output
    circuit: &CircuitRepresentation,
    test_data: Option<(Vec<u8>, Scalar, Vec<Scalar>)>,
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
                .map(|(number, _advice)| format!("    let (a{}, transcript) = read_point(transcript)\n", number + 1))
                .join(""),
            ProofExtractionSteps::Theta => "    let (theta, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::Beta => "    let (beta, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::Gamma => "    let (gamma, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::PermutationsCommited => section
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
                    format!("    let (vanishing_split_{}, transcript) =  read_point(transcript)\n", number + 1)
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
                        "    let (permutations_evaluated_{}_{}, transcript) = read_scalar(transcript)\n",
                        letter,
                        n + 1
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
            // section for halo2 multi open version of KZG
            ProofExtractionSteps::X1 => "    let (x1, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::X2 => "    let (x2, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::X3 => "    let (x3, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::X4 => "    let (x4, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::FCommitment => "    let (f_commitment, transcript) =  read_point(transcript)\n".to_string(),
            ProofExtractionSteps::PI => "    let (pi_term, _) =  read_point(transcript)\n".to_string(),
            ProofExtractionSteps::QEvals => section
                .enumerate()
                .map(|(number, _permutation_common)| {
                    format!("    let (q_eval_on_x3_{}, transcript) = read_scalar(transcript)\n", number + 1)
                })
                .join(""),

            // section for GWC19 version of KZG
            ProofExtractionSteps::V => "    let (v, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::U => "    let (u, transcript) = squeeze_challenge(transcript)\n".to_string(),
            ProofExtractionSteps::Witnesses => section
                .enumerate()
                .map(|(number, _permutation_common)| format!("let (w{}, transcript)) =  read_point(transcript)\n", number + 1))
                .join(""),
        })
        .collect();

    let mut data: HashMap<String, String> = HashMap::new(); // data to bind to mustache template

    data.insert(
        "PUBLIC_INPUTS_COUNT".to_string(),
        circuit.public_inputs.to_string(),
    );

    let public_inputs_lagrange = (1..=circuit.instantiation_data.public_inputs_count)
        .map(|n| format!("i_{}", n))
        .join(", ");
    data.insert("PUBLIC_INPUTS_LAGRANGE".to_string(), public_inputs_lagrange);

    let public_inputs = (1..=circuit.instantiation_data.public_inputs_count)
        .map(|n| format!("    let transcript = common_scalar(i_{}, transcript)\n", n))
        .join("");

    data.insert("PUBLIC_INPUTS".to_string(), public_inputs);

    let public_inputs_names = (1..=circuit.instantiation_data.public_inputs_count)
        .map(|n| format!("i_{}: State<Scalar>", n))
        .join(", ");

    data.insert("PUBLIC_INPUTS_NAMES".to_string(), public_inputs_names);

    let proof_extraction_stage = proof_extraction.join("");
    data.insert("PES".to_string(), proof_extraction_stage);

    data.insert(
        "X_EXPONENT".to_string(),
        circuit.instantiation_data.n_coefficient.to_string(),
    );

    let gates = circuit
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

    let lookup_equations = (1..=circuit.compiled_lookups_equations.0.len())
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

            let l1 = format!("mul(evaluation_at_0, sub(scalarOne, product_eval_{}))", id);
            let l2 = format!("mul(last_evaluation, sub(mul(product_eval_{}, product_eval_{}), product_eval_{}))", id, id, id);
            let left = format!("mul(mul(product_next_eval_{}, add(permuted_input_eval_{}, beta)), add(permuted_table_eval_{}, gamma))", id, id, id);
            let right = format!("mul(mul(product_eval_{}, add(lookup_input_eq{}, beta)), add(lookup_table_eq{}, gamma))", id, id, id);
            let l3 = format!("mul(sub(lookup_left_{}, lookup_right_{}), active_rows)", id, id);
            let l4 = format!("mul(evaluation_at_0, sub(permuted_input_eval_{}, permuted_table_eval_{}))", id, id);
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
                "    let left_set{:?} = mul(permutations_evaluated_{}_2, {}) \n",
                set_number + 1,
                set_id,
                terms
            )
        })
        .join("");
    data.insert("LHS_SETS".to_string(), lhf_sets);

    let permutation_rhs = circuit
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
                "    let right_set{:?} = mul(permutations_evaluated_{}_1, {}) \n",
                set_number + 1,
                set_id,
                terms
            )
        })
        .join("");
    data.insert("RHS_SETS".to_string(), rhf_sets);

    let permutations_combined = if sets_lhs.len() == sets_rhs.len() {
        let sets_number = sets_lhs.len();
        (1..=sets_number).map(|n| {
            format!("    let permutations{} = mul(sub(left_set{}, right_set{}), sub(scalarOne, add(last_evaluation, sum_of_evaluation_for_blinding_factors)))\n", n, n, n)
        }).join("")
    } else {
        panic!("permutations sets have to be equal length")
    };

    data.insert("PERMUTATIONS_COMBINED".to_string(), permutations_combined);

    let gates_count = circuit.compiled_gate_equations.len();
    let permutations_eval_count = circuit.permutations_evaluated_terms.len();
    let sets_count = sets_lhs.len();
    let lookups_count = circuit.compiled_lookups_equations.0.len();

    let mut vanishing_expressions = (1..=gates_count)
        .map(|n| format!("    let expression{} = gate_eq{}\n", n, n))
        .collect::<Vec<_>>();

    let expressions = (1..=permutations_eval_count)
        .map(|n| format!("    let expression{} = term_{}\n", n + gates_count, n))
        .collect::<Vec<_>>();
    vanishing_expressions.extend(expressions);

    let expressions = (1..=sets_count)
        .map(|n| {
            format!(
                "    let expression{} = permutations{}\n",
                n + gates_count + permutations_eval_count,
                n
            )
        })
        .collect::<Vec<_>>();
    vanishing_expressions.extend(expressions);

    let expressions = (1..=lookups_count)
        .flat_map(|n| {
            [
                format!(
                    "    let expression{} = lookup_expression_1_{}\n",
                    ((n - 1) * 5) + 1 + gates_count + permutations_eval_count + sets_count,
                    n
                ),
                format!(
                    "    let expression{} = lookup_expression_2_{}\n",
                    ((n - 1) * 5) + 2 + gates_count + permutations_eval_count + sets_count,
                    n
                ),
                format!(
                    "    let expression{} = lookup_expression_3_{}\n",
                    ((n - 1) * 5) + 3 + gates_count + permutations_eval_count + sets_count,
                    n
                ),
                format!(
                    "    let expression{} = lookup_expression_4_{}\n",
                    ((n - 1) * 5) + 4 + gates_count + permutations_eval_count + sets_count,
                    n
                ),
                format!(
                    "    let expression{} = lookup_expression_5_{}\n",
                    ((n - 1) * 5) + 5 + gates_count + permutations_eval_count + sets_count,
                    n
                ),
            ]
        })
        .collect::<Vec<_>>();
    vanishing_expressions.extend(expressions);

    let _expressions_count = vanishing_expressions.len();

    data.insert(
        "VANISHING_EXPRESSIONS".to_string(),
        vanishing_expressions.join(""),
    );

    let mut vanishing_evaluation = "add(mul(scalarZero, y), expression1)".to_string();
    for n in 2..=(gates_count + permutations_eval_count + sets_count + lookups_count * 5) {
        vanishing_evaluation = format!("add(mul({}, y), expression{})", vanishing_evaluation, n)
    }
    let vanishing_evaluation = format!("    let hEval = {}\n", vanishing_evaluation);
    data.insert("VANISHING_EVALUATION".to_string(), vanishing_evaluation);

    let h_commitments = circuit
        .h_commitments
        .iter()
        .map(|(variable_name, expression)| {
            let term = expression.compile_expression();
            format!("    let {} = {}\n", variable_name, term)
        })
        .join("");
    data.insert("H_COMMITMENTS".to_string(), h_commitments);

    let (unique_grouped_points, commitment_data) = precompute_intermediate_sets(circuit);

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

    let q_evaluations = (1..=circuit.instantiation_data.q_evaluations_count)
        .map(|n| format!("q_eval_on_x3_{}", n))
        .join(", ");
    data.insert("Q_EVALS_FROM_PROOF".to_string(), q_evaluations);

    let commitment_data = commitment_data
        .iter()
        .map(|commitment_data| {
            format!(
                "{}, {}, [{}], [{}]",
                commitment_data.commitment.compile_expression(),
                commitment_data.point_set_index,
                commitment_data.points.iter().map(decode_rotation).join(","),
                commitment_data
                    .evaluations
                    .iter()
                    .map(AikenExpression::compile_expression)
                    .join(",")
            )
        })
        .join("),(");

    let commitment_map = format!("    let commitment_data = [({})]", commitment_data);
    data.insert("COMMITMENT_MAP".to_string(), commitment_map);

    let point_sets = unique_grouped_points
        .iter()
        .map(|set| set.iter().map(decode_rotation).join(","))
        .join("],[");

    let point_sets = format!("     let point_sets = [[{}]]", point_sets);
    data.insert("POINT_SETS".to_string(), point_sets);

    let fixed_commitments_imports = (1..=circuit.instantiation_data.fixed_commitments.len())
        .map(|id| format!("f{}_commitment", id))
        .join(", ");
    let permutation_commitments_imports =
        (1..=circuit.instantiation_data.permutation_commitments.len())
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
        Some((proof, transcript_rep, public_inputs)) => {
            let mut invalid_proof = proof.clone();

            // index points to one of last bytes of las scalar that is part of the proof
            // this should be safe and not result in malformed encoding exception
            // which is likely for flipping Byte for compressed G1 element
            let index = invalid_proof.len() - 1 - 48 - 2;
            let firs_byte = invalid_proof[index];
            let negated_firs_byte = !firs_byte;
            invalid_proof[index] = negated_firs_byte;

            let test_valid_proof_valid_inputs = format!(
                "verifier(#\"{}\", from_int(0x{}), {})",
                hex::encode(proof.clone()),
                hex::encode(transcript_rep.to_bytes_be()),
                public_inputs
                    .iter()
                    .map(|e| format!("from_int(0x{})", hex::encode(e.to_bytes_be())))
                    .join(", ")
            );

            data.insert(
                "TEST_VALID_PROOF_VALID_INPUTS".to_string(),
                test_valid_proof_valid_inputs,
            );

            let test_valid_proof_invalid_inputs = format!(
                "verifier(#\"{}\", from_int(0x{}), {})",
                hex::encode(proof.clone()),
                hex::encode(transcript_rep.to_bytes_be()),
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
                "verifier(#\"{}\", from_int(0x{}), {})",
                hex::encode(invalid_proof),
                hex::encode(transcript_rep.to_bytes_be()),
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
                "verifier(#\"{}\", from_int(0x{}), {})",
                hex::encode(proof.clone()),
                hex::encode(transcript_rep.to_bytes_be()),
                public_inputs
                    .iter()
                    .map(|_e| format!("from_int(0x{})", hex::encode(Scalar::ONE.to_bytes_be())))
                    .join(", ")
            );
            data.insert(
                "TEST_VALID_PROOF_TRIVIAL_INPUTS".to_string(),
                test_valid_proof_trivial_inputs,
            );

            let test_valid_proof_invalid_transcript_rep = format!(
                "verifier(#\"{}\", from_int(0x{}), {})",
                hex::encode(proof),
                hex::encode(transcript_rep.neg().to_bytes_be()),
                public_inputs
                    .iter()
                    .map(|e| format!("from_int(0x{})", hex::encode(e.to_bytes_be())))
                    .join(", ")
            );
            data.insert(
                "TEST_VALID_PROOF_INVALID_TRANSCRIPT_REP".to_string(),
                test_valid_proof_invalid_transcript_rep,
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

pub fn emit_vk_code(
    template_file: &Path,
    aiken_file: &Path,
    circuit: &CircuitRepresentation,
) -> Result<String, RenderError> {
    let mut data: HashMap<String, String> = HashMap::new(); // data to bind to mustache template

    let points = circuit
        .instantiation_data
        .fixed_commitments
        .iter()
        .cloned()
        .map(|g| hex::encode(g.to_bytes()));

    let points = points
        .enumerate()
        .map(|(idx, g1_encoded)| {
            format!(
                "pub const f{}_commitment: G1Element = bls12_381_g1_uncompress(#\"{}\")",
                idx + 1,
                g1_encoded
            )
        })
        .join("\n");

    data.insert("FIXED_COMMITMENTS".to_string(), points);

    let points = circuit
        .instantiation_data
        .permutation_commitments
        .iter()
        .cloned()
        .map(|g| hex::encode(g.to_bytes()));

    let points = points
        .enumerate()
        .map(|(idx, g1_encoded)| {
            format!(
                "pub const p{}_commitment: G1Element = bls12_381_g1_uncompress(#\"{}\")",
                idx + 1,
                g1_encoded
            )
        })
        .join("\n");

    data.insert("PERMUTATION_COMMITMENTS".to_string(), points);

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

    let fixed_commitments = circuit.instantiation_data.fixed_commitments.len();

    let permutation_commitments = circuit.instantiation_data.permutation_commitments.len();

    let fixed = (1..=fixed_commitments)
        .map(|idx| format!("    expect f{}_commitment == f{}_commitment", idx, idx));
    let permutations = (1..=permutation_commitments)
        .map(|idx| format!("    expect p{}_commitment == p{}_commitment", idx, idx));

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
