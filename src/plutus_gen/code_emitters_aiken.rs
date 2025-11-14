use crate::plutus_gen::extraction::data::{CircuitRepresentation, ProofExtractionSteps};
use crate::plutus_gen::extraction::{combine_aiken_expressions, compile_aiken_expressions};
use handlebars::{Handlebars, RenderError};
use itertools::Itertools;
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

pub fn emit_verifier_code(
    template_file: &Path, // aiken mustashe template
    aiken_file: &Path,    // generated aiken file, output
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
                    format!("    let (permuted_input{}, transcript) =  read_point(transcript)\n", number + 1)
                        + &format!("    let (permuted_table{}, transcript) =  read_point(transcript)\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::LookupCommitment => section
                .enumerate()
                .map(|(number, _lookup_commitment)| {
                    format!("    let (lookup_commitment{}, transcript) =  read_point(transcript)\n", number + 1)
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
            ProofExtractionSteps::PI => "    let (pi_term, transcript) =  read_point(transcript)\n".to_string(),
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
                compile_aiken_expressions(gate)
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

    let mut handlebars = Handlebars::new();
    handlebars.set_strict_mode(true);
    handlebars.register_template_file("aiken_template", template_file)?;
    let mut output_file = File::create(aiken_file)?;
    handlebars.render_to_write("aiken_template", &data, &mut output_file)?;
    handlebars.render("aiken_template", &data)
}
