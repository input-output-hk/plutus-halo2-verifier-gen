//! High level code for generating Halo2 verifier in Plinth
//! PCS related code is in `pcs` module directly.

use crate::plutus_gen::extraction::data::languages::plinth::*;
use crate::plutus_gen::extraction::data::{
    CircuitRepresentation, ProofExtractionSteps, RotationDescription, constants::*,
};
use crate::plutus_gen::extraction::pcs::{ExtractPCS, PCSType};

use group::{GroupEncoding, prime::PrimeCurveAffine};
use handlebars::{Handlebars, RenderError};
use itertools::Itertools;
use std::{collections::HashMap, fs::File, path::Path};

pub fn emit_verifier_code<PCS>(
    template_file: &Path, // haskell mustashe template
    haskell_file: &Path,  // generated haskell file, output
    test_template: &Path,
    test_plutus_template: &Path,
    test_haskell_template: &Path,
    test_compiled_template: &Path,
    circuit: &CircuitRepresentation<PCS>,
) -> Result<String, RenderError>
where
    PCS: ExtractPCS,
{
    // Data structure we write the code in and bind with mustache template
    let mut data: HashMap<String, String> = HashMap::new();

    // Lifting verification key information
    {
        let fixed_commitments_lifts = (1..=circuit.proof_instantiation_data.fixed_commitments.len()).map(|id| {
        format!("f{}_commitment :: BuiltinBLS12_381_G1_Element\nf{}_commitment = $(lift VKConstants.f{}_commitment)\n\n", id, id, id)
    }).join("");
        data.insert(
            "FIXED_COMMITMENT_LIFTS".to_string(),
            fixed_commitments_lifts,
        );

        let permutation_commitments_lifts = (1..=circuit.proof_instantiation_data.permutation_commitments.len()).map(|id| {
        format!("p{}_commitment :: BuiltinBLS12_381_G1_Element\np{}_commitment = $(lift VKConstants.p{}_commitment)\n\n", id, id, id)
    }).join("");

        data.insert(
            "PERMUTATION_COMMITMENT_LIFTS".to_string(),
            permutation_commitments_lifts,
        );
    }

    let nb_public_inputs = circuit.proof_instantiation_data.public_inputs_count;
    let nb_committed_instances = circuit.proof_instantiation_data.committed_instances_count;
    let committed_instances_supported = circuit
        .proof_instantiation_data
        .committed_instances_supported;

    // Handling committed instances
    let ci_absorption = if committed_instances_supported && nb_committed_instances > 0 {
        format!("  !ci{} <- M.commonG1 committedInputs\n", 1)
    } else {
        String::new()
    };
    data.insert("ABSORB_COMMITTED_INSTANCES".to_string(), ci_absorption);

    // Handling public inputs
    {
        data.insert(
            "PUBLIC_INPUTS_COUNT".to_string(),
            nb_public_inputs.to_string(),
        );

        data.insert(
            "PUBLIC_INPUTS_TYPES".to_string(),
            (1..=nb_public_inputs)
                .map(|_| "Scalar ->".to_string())
                .join(" "),
        );

        let absorb_nb_public_inputs =
            format!("  _ <- M.commonScalar (mkScalar {})\n", nb_public_inputs);

        let absorb_public_inputs = (1..=nb_public_inputs)
            .map(|n| format!("  !i{} <- M.commonScalar (parsedInputs !! {})\n", n, n - 1))
            .join("");

        let mut public_inputs =
            String::with_capacity(absorb_nb_public_inputs.len() + absorb_public_inputs.len());
        public_inputs.push_str(&absorb_nb_public_inputs);
        public_inputs.push_str(&absorb_public_inputs);
        data.insert("ABSORB_PUBLIC_INPUTS".to_string(), public_inputs);
    }

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
            ProofExtractionSteps::XCoordinate => {
                let squeezing_x = "  !x <- M.squeezeChallenge\n".to_string();
                let scaling_x = format!(
                    "  let !xn_minus_one = powMod x ({}-1)\n",
                    circuit.proof_instantiation_data.n_coefficient.to_string()
                )
                .to_string();
                let scaling_x_again = "  let !xn = xn_minus_one * x\n".to_string();
                let mut to_write_down = String::with_capacity(
                    squeezing_x.len() + scaling_x.len() + scaling_x_again.len(),
                );
                to_write_down.push_str(&squeezing_x);
                to_write_down.push_str(&scaling_x);
                to_write_down.push_str(&scaling_x_again);
                to_write_down
            }
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
            ProofExtractionSteps::Trash => "  !trash <- M.squeezeChallenge\n".to_string(),
            ProofExtractionSteps::TrashCommitment => section
                .enumerate()
                .map(|(number, _trashcan)| {
                    format!("  !trashcanCommitment{} <- M.readPoint\n\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::TrashEval => section
                .enumerate()
                .map(|(number, _trashcan)| {
                    format!("  !trashcanEval{} <- M.readScalar\n", number + 1)
                })
                .join(""),
            ProofExtractionSteps::CommittedInstanceEval => section.enumerate().map(|(number, _ci)| {
                match (committed_instances_supported,nb_committed_instances) {
                    (false, _) => panic!("This case should never happen, as we should not have any CommittedInstanceEval"),
                    (true, 0) => {assert!(number == 0); format!("\n  let !instanceEval1 = scalarZero\n")},
                    (true, _) => format!("  !instanceEval{} <-  M.readScalar\n", number + 1)
                }
            }).join(""),
            ProofExtractionSteps::InstanceEval => section.enumerate().map(|(number, _i)| {
                let offset = nb_committed_instances;
                if nb_public_inputs == 0 {
                    format!("  let !instanceEval{} = scalarZero\n", number + offset + 1)
                } else {
                let public_inputs_lagrange = (1..=nb_public_inputs).map(|n| format!("i{}", n)).join(", ");
                let lagrange = format!("  let !lagrange_polynomial_instances = lagrangePolynomialBasis x xn barycentricWeight rotations_for_instances\n");
                let instance = format!("  let !instanceEval{} = innerProduct lagrange_polynomial_instances  [{}]\n\n", number + offset + 1, public_inputs_lagrange);
                let mut all_strings_instance = String::with_capacity(
                    lagrange.len() + instance.len(),
                );
                all_strings_instance.push_str(&lagrange);
                all_strings_instance.push_str(&instance);
                all_strings_instance
            }
            }).join(""),
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
                .map(|(number, _step)| PCS::step_to_plinth(section_type.clone(), number + 1))
                .join("")
        })
        .collect::<Vec<_>>();

    let proof_extraction_stage = proof_extraction.join("") + &pcs_extraction.join("");
    data.insert("PES".to_string(), proof_extraction_stage);

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
                    "      !gate_eq{:?} = {}\n",
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
                    "      !lookup_table_eq{:?} = {}\n",
                    id + 1,
                    combine_plinth_expressions(gate.clone(), THETA_STR)
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
                    "      !lookup_input_eq{:?} = {}\n",
                    id + 1,
                    combine_plinth_expressions(gate.clone(), THETA_STR)
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

        // Adding permutation evaluation expressions
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
                    sets_lhs.insert(*set, format!("{} * left{:?}", existing, id + 1));
                } else {
                    sets_lhs.insert(*set, format!("left{:?}", id + 1));
                };
                let term = expression.compile_expression();
                format!("      !left{:?} = {} --part of set {}\n", id + 1, term, set)
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
                    "      !left_set{:?} = {} * {} \n",
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

        // Combining right permutation expressions
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

        // Combining left and right permutation expressions
        let permutations_combined = if sets_lhs.len() == sets_rhs.len() {
            let sets_number = sets_lhs.len();
            (1..=sets_number).map(|n| {
            format!("      !permutations{} = (left_set{} - right_set{}) * ({} - ({} + sum_of_evaluation_for_blinding_factors))\n", n, n, n, ONE_STR, EVAL_LAST_STR)
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
                    "      !trashcanExp{} = {} - (({} - {}) * trashcanEval{})\n",
                    id + 1,
                    combine_plinth_expressions(expression.clone(), TRASH_STR),
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
            .map(|n| format!("      !expression{} = gate_eq{}\n", n, n))
            .collect::<Vec<_>>();
        total_nb_expressions += gates_count;

        // Adding permutation evaluation expressions to vanishing
        let expressions = (1..=permutations_eval_count)
            .map(|n| {
                format!(
                    "      !expression{} = term{}\n",
                    n + total_nb_expressions,
                    n
                )
            })
            .collect::<Vec<_>>();
        total_nb_expressions += permutations_eval_count;
        vanishing_expressions.extend(expressions);

        // Adding combined permutation expressions to vanishing
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

        // Adding lookup expressions to vanishing
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
        total_nb_expressions += lookups_count * 5;
        vanishing_expressions.extend(expressions);

        // Adding trashcan expressions to vanishing
        let expressions = (1..=trashcans_count)
            .map(|n| {
                format!(
                    "      !expression{} = trashcanExp{}\n",
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
        let mut vanishing_evaluation = format!("({} * y + expression1)", ZERO_STR);
        for n in 2..=total_nb_expressions {
            vanishing_evaluation = format!("({} * y + expression{})", vanishing_evaluation, n)
        }
        let vanishing_evaluation = format!("      !hEval = {}\n", vanishing_evaluation);
        data.insert("VANISHING_EVALUATION".to_string(), vanishing_evaluation);

        // Adding vanishing_g and h_commitments expressions
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
    }

    let (unique_grouped_points, commitment_data) = PCS::precompute_intermediate_sets(circuit);

    let commitment_data_str = commitment_data
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

    // Adding commtment map
    let commitment_map = format!("      !commitment_data = [({})]", commitment_data_str);
    data.insert("COMMITMENT_MAP".to_string(), commitment_map);

    let point_sets = unique_grouped_points
        .iter()
        .map(|set| set.iter().map(RotationDescription::to_string).join(","))
        .join("],[");

    // Adding point sets
    let point_sets = format!("      !point_sets = [[{}]]", point_sets);
    data.insert("POINT_SETS".to_string(), point_sets);

    if PCS::pcs_type() == PCSType::Halo2MultiOpen {
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

        let q_evaluations = PCS::pcs_data_plinth(&circuit);
        data.insert("Q_EVALS_FROM_PROOF".to_string(), q_evaluations);
    }

    let recursion_lift = circuit.proof_instantiation_data.recursion_vks.clone().map_or(String::new(), |recursion_vks| {
        if recursion_vks.is_empty() {
            return String::new();
        }

        recursion_vks.iter().map(|vki| {
            (1..=vki.fixed_commitments.len())
                .map(|id| {
                    format!("f{}_{} :: BuiltinBLS12_381_G1_Element\nf{}_{} = $(lift VKConstants.f{}_{})\n\n",
                        id, vki.name, id, vki.name, id, vki.name)
                })
                .chain(
                    (1..=vki.permutation_commitments.len()).map(|id| {
                        format!("p{}_{} :: BuiltinBLS12_381_G1_Element\np{}_{} = $(lift VKConstants.p{}_{})\n\n",
                            id, vki.name, id, vki.name, id, vki.name)
                    })
                )
                .collect::<String>()
        }).join("")
    });
    data.insert("RECURSION_COMMITMENT_LIFTS".to_string(), recursion_lift);

    let recursion_map = circuit.proof_instantiation_data.recursion_vks.clone().map_or("".to_string(), |recursion_vks| {

            let serialized_acc = 2 * 2 * 7; // 2 points, each with x and y coordinate, each coordinate is 32 bytes when serialized

            let (fixed_bases, fixed_bases_len) = {
                let mut ivc_fixed_bases = Vec::new();
                let mut size = 0;

                circuit.proof_instantiation_data.fixed_commitments.iter().enumerate().for_each(|(i, _)| {
                    ivc_fixed_bases.push(format!("f{}", i ));
                    size += 1;
                });
                circuit.proof_instantiation_data.permutation_commitments.iter().enumerate().for_each(|(i, _)| {
                    ivc_fixed_bases.push(format!("p{}", i ));
                    size += 1;
                });

                recursion_vks.iter().for_each(|vki| {
                    vki.fixed_commitments.iter().enumerate().for_each(|(i, _)| {
                        ivc_fixed_bases.push(format!("f{}_{}",i, vki.name));
                        size += 1;
                    });

                    vki.permutation_commitments.iter().enumerate().for_each(|(i, _)| {
                        ivc_fixed_bases.push(format!("p{}_{}",i, vki.name));
                        size += 1;
                    });
                });

                (ivc_fixed_bases, size)
            };

            assert!(nb_public_inputs >= (fixed_bases_len + serialized_acc), "Not enough public inputs to support recursion. Required at least {}, but only {} provided.", fixed_bases_len + serialized_acc, nb_public_inputs);

            let acc_left : String = {
                let serialized_x = format!("      !acc_left_x = mkFp ({})\n", (0..7).fold(ZERO_STR.to_string(), |acc, i| {
                        format!("({} * 72057594037927936 + (unScalar i{}))", acc, nb_public_inputs - fixed_bases_len - 3*7 - 1 - i)
                    }).to_string());

                let serialized_y = format!("      !acc_left_y = mkFp ({})\n", (0..7).fold(ZERO_STR.to_string(), |acc, i| {
                        format!("({} * 72057594037927936 + (unScalar i{}))", acc, nb_public_inputs - fixed_bases_len - 2*7 - 1 - i)
                    }).to_string());

                let uncompressed  = "      !compressed_acc_left = BlsUtils.fromCoordsG1Point(acc_left_x, acc_left_y) \n".to_string();

               [serialized_x, serialized_y, uncompressed].iter().join(",")
            };

            let acc_right : String = {
                let serialized_x = format!("      !acc_right_x_int = mkFp ({})\n", (0..7).fold(ZERO_STR.to_string(), |acc, i| {
                        format!("({} * 72057594037927936 + (unScalar i{}))", acc, nb_public_inputs - fixed_bases_len - 7 - 1 - i)
                    }).to_string());

                let serialized_y = format!("      !acc_right_y_int = mkFp ({})\n", (0..7).fold(ZERO_STR.to_string(), |acc, i| {
                        format!("({} * 72057594037927936 + (unScalar i{}))", acc, nb_public_inputs - fixed_bases_len - 1 - i)
                    }).to_string());

                let uncompressed = "      !compressed_acc_right = BlsUtils.fromCoordsG1Point(acc_right_x_int, acc_right_y_int) \n".to_string();

               [serialized_x, serialized_y, uncompressed].iter().join(",")
            };

            let acc_fixed : String = if fixed_bases_len > 0 {
            format!("      !acc_fixed = {}", fixed_bases.iter().enumerate().fold(ZERO_STR.to_string(), |acc, (i, name)| {
                format!("({} + (scale i{} {}))", acc, nb_public_inputs - fixed_bases_len + i, name )
            })) } else { "".to_string() };

            let acc_right_final : String = if fixed_bases_len > 0 {format!("      !acc_right_final = acc_right + acc_fixed\n")} else {
                format!("      !acc_right_final = acc_right\n")
            };

            let challenge = format!("      !challenge =  mkScalar(byteStringToInteger (blake2b_256 ((bls12_381_G1_compress el) <> (bls12_381_G1_compress er) <> (bls12_381_G1_compress acc_left) <> (bls12_381_G1_compress acc_right_final))) `modulo` bls12_381_field_prime)\n");

            let updated_el = format!("      !el = el +  (scale challenge acc_left)\n");
            let updated_er = format!("      !er = er + (scale challenge acc_right_final)\n");

            [acc_left, acc_right, acc_fixed, acc_right_final, challenge, updated_el, updated_er].iter().join(",")
        });
    data.insert("RECURSION_ACCUMULATOR".to_string(), recursion_map);

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

    {
        let mut vars = Vec::new();
        if nb_committed_instances > 0 {
            vars.push("committedInputs".to_string());
        }
        if nb_public_inputs > 0 {
            vars.push("parsedInputs".to_string());
        }

        data.insert("COMMITTED_INSTANCES_AND_INSTANCE_VARS".to_string(), {
            vars.iter().join(" ")
        });
        data.insert("SEP_COMMITTED_INSTANCES_AND_INSTANCE_VARS".to_string(), {
            vars.iter().join(", ")
        });

        let mut var_types = Vec::new();
        if nb_committed_instances > 0 {
            var_types.push("BuiltinBLS12_381_G1_Element".to_string());
        }
        if nb_public_inputs > 0 {
            var_types.push("[Scalar]".to_string());
        }
        data.insert("COMMITTED_INSTANCES_AND_INSTANCE_TYPES".to_string(), {
            if var_types.is_empty() {
                String::new()
            } else {
                var_types.iter().join(" -> ") + " ->"
            }
        });

        let mut handlebars = Handlebars::new();
        handlebars.set_strict_mode(true);
        handlebars.register_template_file("test_template", test_template)?;
        let mut output_file = File::create("plinth-verifier/plutus-halo2/test/Test.hs")?;
        handlebars.render_to_write("test_template", &data, &mut output_file)?;
        handlebars.render("test_template", &data)?;

        let mut handlebars = Handlebars::new();
        handlebars.set_strict_mode(true);
        handlebars.register_template_file("test_haskell_template", test_haskell_template)?;
        let mut output_file =
            File::create("plinth-verifier/plutus-halo2/test/Generic/VerificationTestHaskell.hs")?;
        handlebars.render_to_write("test_haskell_template", &data, &mut output_file)?;
        handlebars.render("test_haskell_template", &data)?;

        let mut handlebars = Handlebars::new();
        handlebars.set_strict_mode(true);
        handlebars.register_template_file("test_plutus_template", test_plutus_template)?;
        let mut output_file =
            File::create("plinth-verifier/plutus-halo2/test/Generic/VerificationTestPlutus.hs")?;
        handlebars.render_to_write("test_plutus_template", &data, &mut output_file)?;
        handlebars.render("test_plutus_template", &data)?;

        let mut handlebars = Handlebars::new();
        handlebars.set_strict_mode(true);
        handlebars.register_template_file("test_compiled_template", test_compiled_template)?;
        let mut output_file =
            File::create("plinth-verifier/plutus-halo2/test/Generic/VerifyCompiled.hs")?;
        handlebars.render_to_write("test_compiled_template", &data, &mut output_file)?;
        handlebars.render("test_compiled_template", &data)?;
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

pub fn emit_vk_code<PCS>(
    template_file: &Path, // haskell mustashe template
    haskell_file: &Path,  // generated haskell file, output
    circuit: &CircuitRepresentation<PCS>,
) -> Result<String, RenderError>
where
    PCS: ExtractPCS,
{
    let mut data: HashMap<String, String> = HashMap::new(); // data to bind to mustache template

    let points = circuit
        .proof_instantiation_data
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
    let exports = (1..=circuit.proof_instantiation_data.fixed_commitments.len())
        .map(|id| format!("  f{}_commitment,\n", id))
        .join("");
    let assignment = circuit.proof_instantiation_data.fixed_commitments.clone().iter().enumerate().map(|(id, point)| {
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
        .proof_instantiation_data
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
    let exports = (1..=circuit
        .proof_instantiation_data
        .permutation_commitments
        .len())
        .map(|id| format!("  p{}_commitment,\n", id))
        .join("");
    let assignment = circuit.proof_instantiation_data.permutation_commitments.clone().iter().enumerate().map(|(id, point)| {
        if point.is_identity().into() {
            format!("p{}_commitment :: BuiltinBLS12_381_G1_Element\np{}_commitment = (bls12_381_G1_uncompress bls12_381_G1_compressed_zero)\n", id + 1, id + 1)
        } else {
            format!("p{}_commitment :: BuiltinBLS12_381_G1_Element\np{}_commitment = p_commitments !! {}\n", id + 1, id + 1, id)
        }
    }).join("");

    data.insert("PERMUTATION_COMMITMENTS".to_string(), points);
    data.insert("PERMUTATION_COMMITMENTS_EXPORTS".to_string(), exports);
    data.insert("PERMUTATION_COMMITMENT_G1".to_string(), assignment);

    let (points, exports, assignment) = circuit.proof_instantiation_data.recursion_vks.clone().map_or((String::new(), String::new(), String::new()), |recursion_vks| {
        if recursion_vks.len() == 0 {
            return (String::new(), String::new(), String::new());
        }

        let points = format!("rec_commitment_val_pairs :: [(Integer, Integer)]\n
rec_commitment_val_pairs =[{}]", recursion_vks.iter().flat_map(|vki| {
            vki.fixed_commitments.iter().map(|a| {
                format!(
                    "    (0x{}, 0x{})",
                    hex::encode(a.x().to_bytes_be()),
                    hex::encode(a.y().to_bytes_be())
                )
            }).chain(vki.permutation_commitments.iter().map(|a| {
                format!(
                    "    (0x{}, 0x{})",
                    hex::encode(a.x().to_bytes_be()),
                    hex::encode(a.y().to_bytes_be())
                )
            }))
        }).join(",\n"));

        let exports = recursion_vks.iter().flat_map(|vki| {
            (1..=vki.fixed_commitments.len()).map(|id| {
                format!("  f{}_{},\n", id, vki.name) }
            ).chain((1..=vki.permutation_commitments.len()).map(|id| {
                format!("  p{}_{},\n", id, vki.name) 
            }))
        }).join(",\n");

        let mut offset = 0;
        let assignments = recursion_vks.iter().map(|vki| {
            let vki_fixed_len = vki.fixed_commitments.len();
            let commitments = format!("rec_commitments :: [BuiltinBLS12_381_G1_Element]\n
rec_commitments = commitments rec_commitments_val_pairs\n\n{}", 
                vki.fixed_commitments.iter().enumerate().map(|(id, point)| {
                    if point.is_identity().into() {
                        format!("f{}_{} :: BuiltinBLS12_381_G1_Element\nf{}_{} = (bls12_381_G1_uncompress bls12_381_G1_compressed_zero)\n", id + 1, vki.name, id + 1, vki.name)
                    } else {
                        format!("f{}_{} :: BuiltinBLS12_381_G1_Element\nf{}_{} = rec_commitments !! {}\n", id + 1, vki.name, id + 1, vki.name, id + offset)
                    }
                }).chain(vki.permutation_commitments.iter().enumerate().map(|(id, point)| {
                    if point.is_identity().into() {
                        format!("p{}_{} :: BuiltinBLS12_381_G1_Element\np{}_{} = (bls12_381_G1_uncompress bls12_381_G1_compressed_zero)\n", id + 1, vki.name, id + 1, vki.name)
                    } else {
                        format!("p{}_{} :: BuiltinBLS12_381_G1_Element\np{}_{} = rec_commitments !! {}\n", id + 1, vki.name, id + 1, vki.name, id + offset + vki_fixed_len)
                    }
                })).join(""));
            offset += vki_fixed_len + vki.permutation_commitments.len();
            commitments
        }).join("");

        (points, exports, assignments)
    });
    data.insert("RECURSION_COMMITMENTS".to_string(), points);
    data.insert("RECURSION_COMMITMENTS_EXPORTS".to_string(), exports);
    data.insert("RECURSION_COMMITMENT_G1".to_string(), assignment);

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

    let mut handlebars = Handlebars::new();
    handlebars.set_strict_mode(true);
    handlebars.register_template_file("haskell_template", template_file)?;
    let mut output_file = File::create(haskell_file)?;
    handlebars.render_to_write("haskell_template", &data, &mut output_file)?;
    handlebars.render("haskell_template", &data)
}
