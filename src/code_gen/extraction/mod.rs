use crate::code_gen::code_emitters::{emit_verifier_code, emit_vk_code};
use crate::code_gen::extraction::data::{
    CircuitRepresentation, ProofExtractionSteps, Query, RotationDescription,
};
use crate::code_gen::extraction::utils::{compile_expressions, get_any_query_index};
use blstrs::{Bls12, G1Affine, G2Affine, Scalar};
use ff::Field;
use halo2_proofs::halo2curves::group::Curve;
use halo2_proofs::halo2curves::group::prime::PrimeCurveAffine;
use halo2_proofs::plonk::{Any, Error, VerifyingKey};
use halo2_proofs::poly::Rotation;
use halo2_proofs::poly::gwc_kzg::GwcKZGCommitmentScheme;
use halo2_proofs::poly::kzg::KZGCommitmentScheme;
use halo2_proofs::poly::kzg::params::ParamsKZG;
use itertools::Itertools;
use log::info;

pub mod data;
mod utils;

type Scheme = GwcKZGCommitmentScheme<Bls12>;

// todo transcript_representation is off comparing to old version of halo2 but it may be ok

pub fn extract_circuit(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, Scheme>,
    instances: &[&[&[Scalar]]],
    verifier_template_file: String,
    vk_template_file: String,
    g2_encoder: fn(G2Affine) -> String,
) -> Result<CircuitRepresentation, Error> {
    let chunk_len = vk.cs().degree() - 2;

    for instances in instances.iter() {
        if instances.len() != vk.cs().num_instance_columns() {
            return Err(Error::InvalidInstances);
        }
    }

    let mut circuit_description: CircuitRepresentation = CircuitRepresentation::default();

    if instances.len() > 1 {
        panic!("More than 1 proof for processing");
    }

    for instance in instances.iter() {
        for instance in instance.iter() {
            for value in instance.iter() {
                // transcript.common(value)?;
                info!("writ public input (instance) into the transcript");
                circuit_description.public_inputs += 1;
                info!("{:?}", value);
                info!("--------------------------------");
            }
        }
    }

    let mut advice_commitments = vec![G1Affine::generator(); vk.cs().num_advice_columns()];
    let mut challenges = vec![Scalar::ZERO; vk.cs().num_challenges()];

    let all_phases = vk.cs().advice_column_phase();
    let max_phase = all_phases
        .iter()
        .max()
        .expect("No max_phase for phases found");
    let all_phases = 0..=(*max_phase);

    for current_phase in all_phases {
        for (phase, _commitment) in vk
            .cs()
            .advice_column_phase()
            .iter()
            .zip(advice_commitments.iter_mut())
        {
            if current_phase == *phase {
                circuit_description
                    .proof_extraction_steps
                    .push(ProofExtractionSteps::AdviceCommitments);
            }
        }
        for (phase, _challenge) in vk.cs().challenge_phase().iter().zip(challenges.iter_mut()) {
            if current_phase == *phase {
                circuit_description
                    .proof_extraction_steps
                    .push(ProofExtractionSteps::SqueezeChallenge);
            }
        }
    }

    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::Theta);

    let num_lookups_permuted = vk.cs().lookups().len();
    (0..num_lookups_permuted).for_each(|_argument| {
        circuit_description
            .proof_extraction_steps
            .push(ProofExtractionSteps::LookupPermuted);
    });

    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::Beta);

    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::Gamma);

    let num_permutation_commitments = vk.cs().permutation().columns.chunks(chunk_len).len();

    (0..num_permutation_commitments).for_each(|_| {
        circuit_description
            .proof_extraction_steps
            .push(ProofExtractionSteps::PermutationsCommited);
    });

    (0..num_lookups_permuted).for_each(|_| {
        circuit_description
            .proof_extraction_steps
            .push(ProofExtractionSteps::LookupCommitment)
    });

    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::VanishingRand);

    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::YCoordinate);

    (0..vk.get_domain().get_quotient_poly_degree()).for_each(|_| {
        circuit_description
            .proof_extraction_steps
            .push(ProofExtractionSteps::VanishingSplit);
    });

    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::XCoordinate);

    circuit_description.instantiation_data.fixed_commitments = vk
        .fixed_commitments()
        .iter()
        .map(|p| p.to_affine())
        .collect();
    circuit_description
        .instantiation_data
        .permutation_commitments = vk
        .permutation()
        .commitments()
        .iter()
        .map(|p| p.to_affine())
        .collect();
    circuit_description.instantiation_data.public_inputs_count = instances[0][0].len();

    circuit_description.instantiation_data.n_coefficient = vk.n();
    circuit_description.instantiation_data.s_g2 = params.s_g2().to_affine();
    circuit_description.instantiation_data.omega = vk.get_domain().get_omega();
    circuit_description.instantiation_data.inverted_omega = vk.get_domain().get_omega_inv();
    circuit_description.instantiation_data.barycentric_weight = Scalar::from(vk.n())
        .invert()
        .expect("there should be an inverse");
    circuit_description
        .instantiation_data
        .transcript_representation = vk.transcript_repr();
    circuit_description.instantiation_data.blinding_factors = vk.cs().blinding_factors();

    let (min_rotation, max_rotation) =
        vk.cs()
            .instance_queries()
            .iter()
            .fold((0, 0), |(min, max), (_, rotation)| {
                if rotation.0 < min {
                    (rotation.0, max)
                } else if rotation.0 > max {
                    (min, rotation.0)
                } else {
                    (min, max)
                }
            });
    let max_instance_len = instances
        .iter()
        .flat_map(|instance| instance.iter().map(|instance| instance.len()))
        .max_by(Ord::cmp)
        .unwrap_or_default();
    let rotations = -max_rotation..max_instance_len as i32 + min_rotation.abs();

    circuit_description
        .instantiation_data
        .omega_rotation_count_for_instances = rotations.len();

    (0..vk.cs().advice_queries().len()).for_each(|_| {
        circuit_description
            .proof_extraction_steps
            .push(ProofExtractionSteps::AdviceEval);
    });

    (0..vk.cs().fixed_queries().len()).for_each(|_| {
        circuit_description
            .proof_extraction_steps
            .push(ProofExtractionSteps::FixedEval);
    });

    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::RandomEval);

    // for each commitment do a PermutationCommon
    vk.permutation()
        .commitments()
        .iter()
        .enumerate()
        .for_each(|_| {
            circuit_description
                .proof_extraction_steps
                .push(ProofExtractionSteps::PermutationCommon);
        });

    let letters = 'a'..='z';
    let last_index = num_permutation_commitments - 1;
    (0..num_permutation_commitments)
        .zip(letters)
        .enumerate()
        .for_each(|(index, (_, letter))| {
            circuit_description
                .proof_extraction_steps
                .push(ProofExtractionSteps::PermutationEval(letter));
            circuit_description
                .proof_extraction_steps
                .push(ProofExtractionSteps::PermutationEval(letter));

            if index != last_index {
                circuit_description
                    .proof_extraction_steps
                    .push(ProofExtractionSteps::PermutationEval(letter));
            }
        });

    (0..num_lookups_permuted).for_each(|_| {
        circuit_description
            .proof_extraction_steps
            .push(ProofExtractionSteps::LookupEval)
    });

    let mut compiled_gates: Vec<_> = vk
        .cs()
        .gates()
        .iter()
        .flat_map(move |gate| gate.polynomials().iter().map(compile_expressions))
        .collect();

    // fold expressions for particular lookup
    // initial ACC = ZERO
    // folding : ACC = (acc * theta + eval)
    // where eval is subsequent expressions
    // separate for input and for table expression

    let compiled_lookups: Vec<(String, String)> = vk
        .cs()
        .lookups()
        .iter()
        .map(|argument| {
            let input_expressions: Vec<_> = argument
                .input_expressions()
                .iter()
                .map(compile_expressions)
                .collect();

            let folded_input_expressions = input_expressions
                .iter()
                .fold("scalarZero".to_string(), |acc, eval| {
                    format!("({} * theta + {})", acc, eval)
                });

            let table_expressions: Vec<_> = argument
                .table_expressions()
                .iter()
                .map(compile_expressions)
                .collect();

            let folded_table_expressions = table_expressions
                .iter()
                .fold("scalarZero".to_string(), |acc, eval| {
                    format!("({} * theta + {})", acc, eval)
                });

            (folded_input_expressions, folded_table_expressions)
        })
        .collect();

    circuit_description
        .compiled_gate_equations
        .append(&mut compiled_gates);

    circuit_description.compiled_lookups_equations = compiled_lookups.iter().cloned().unzip();

    //todo add stages to extract data for final pairing check preparation

    info!("permutations expressions");
    // group to get permutation sets
    let sets: Vec<_> = circuit_description
        .proof_extraction_steps
        .iter()
        .filter(|e| matches!(e, ProofExtractionSteps::PermutationEval(_)))
        .chunk_by(|e| match e {
            ProofExtractionSteps::PermutationEval(code) => code,
            _ => panic!("unexpected proof extraction step"),
        })
        .into_iter()
        .map(|(c, _)| c)
        .collect();

    // todo think about errors returned
    let first_set = sets
        .first()
        .ok_or("unable to get first element of the set")
        .map_err(|_e| Error::Synthesis)?;
    let last_set = sets
        .last()
        .ok_or("unable to get last element of the set")
        .map_err(|_e| Error::Synthesis)?;
    let shifted_sets: Vec<_> = sets.iter().skip(1).zip(sets.iter()).collect();

    let mut terms: Vec<String> = Vec::new();

    terms.push(format!(
        "evaluation_at_0 * (scalarOne - permutations_evaluated_{}_1)",
        first_set
    ));
    terms.push(
        format!("last_evaluation * (permutations_evaluated_{}_1 * permutations_evaluated_{}_1 - permutations_evaluated_{}_1)",
                last_set,
                last_set,
                last_set));

    for (next, current) in shifted_sets {
        let term = format!(
            "(permutations_evaluated_{}_1 - permutations_evaluated_{}_3) * evaluation_at_0",
            next, current
        );
        terms.push(term);
    }

    circuit_description.permutations_evaluated_terms = terms;

    let permutations_common = circuit_description
        .proof_extraction_steps
        .iter()
        .filter(|e| matches!(e, ProofExtractionSteps::PermutationCommon))
        .count();

    sets.iter()
        .zip(vk.cs().permutation().columns.chunks(chunk_len))
        // replace with proof extractions permutations_common
        .zip(1..=permutations_common)
        .enumerate()
        .for_each(|(chunk_index, ((set, columns), _))| {
            columns.iter().enumerate().for_each(|(idx, &column)| {
                let permutation_index = (chunk_index * chunk_len) + idx + 1;
                let eval_index = get_any_query_index(vk, column, Rotation::cur()) + 1;
                match column.column_type() {
                    Any::Advice(_) => {
                        let term: String = format!(
                            "(adviceEval{:?} + (beta * permutationCommon{:?}) + gamma)",
                            eval_index, permutation_index
                        );
                        circuit_description
                            .permutation_terms_left
                            .push((**set, term));
                    }
                    Any::Fixed => {
                        let term: String = format!(
                            "(fixedEval{:?} + (beta * permutationCommon{:?}) + gamma)",
                            eval_index, permutation_index
                        );
                        circuit_description
                            .permutation_terms_left
                            .push((**set, term));
                    }
                    Any::Instance => {
                        let term: String = format!(
                            "(instanceEval{:?} + (beta * permutationCommon{:?}) + gamma)",
                            eval_index, permutation_index
                        );
                        circuit_description
                            .permutation_terms_left
                            .push((**set, term));
                    }
                }
            });

            columns.iter().enumerate().for_each(|(idx, &column)| {
                let power = chunk_index * chunk_len + idx;
                let eval_index = get_any_query_index(vk, column, Rotation::cur()) + 1;
                match column.column_type() {
                    Any::Advice(_) => {
                        let term: String = format!(
                            "(adviceEval{:?} + (beta * x) * (powMod scalarDelta {:?}) + gamma)",
                            eval_index, power
                        );
                        circuit_description
                            .permutation_terms_right
                            .push((**set, term));
                    }
                    Any::Fixed => {
                        let term: String = format!(
                            "(fixedEval{:?} + (beta * x) * (powMod scalarDelta {:?}) + gamma)",
                            eval_index, power
                        );
                        circuit_description
                            .permutation_terms_right
                            .push((**set, term));
                    }
                    Any::Instance => {
                        let term: String = format!(
                            "(instanceEval{:?} + (beta * x) * (powMod scalarDelta {:?}) + gamma)",
                            eval_index, power
                        );
                        circuit_description
                            .permutation_terms_right
                            .push((**set, term));
                    }
                }
            });
        });

    let vanishing_splits_count = circuit_description
        .proof_extraction_steps
        .iter()
        .filter(|e| matches!(e, ProofExtractionSteps::VanishingSplit))
        .count();

    circuit_description.h_commitments.push(format!("!hCommitment1 = scale xn (bls12_381_G1_uncompress bls12_381_G1_compressed_zero) + vanishingSplit{:?}", vanishing_splits_count));
    for i in 1..(vanishing_splits_count - 1) {
        // render last on as vanishing_g
        circuit_description.h_commitments.push(format!(
            "!hCommitment{:?} = scale xn hCommitment{:?} + vanishingSplit{:?}",
            i + 1,
            i,
            vanishing_splits_count - i
        ));
    }
    circuit_description.h_commitments.push(format!(
        "!vanishing_g = scale xn hCommitment{} + vanishingSplit1",
        vanishing_splits_count - 1
    ));

    fn decode(input: i32) -> RotationDescription {
        match input {
            -1 => RotationDescription::Previous,
            0 => RotationDescription::Current,
            1 => RotationDescription::Next,
            _ => panic!("unknown number {} for rotation", input),
        }
    }

    vk.cs()
        .advice_queries()
        .iter()
        .enumerate()
        .for_each(|(query_index, &(column, at))| {
            circuit_description.advice_queries.push(Query {
                commitment: format!("a{:?}", column.index() + 1),
                evaluation: format!("adviceEval{:?}", query_index + 1),
                point: decode(at.0),
            });
        });

    vk.cs()
        .fixed_queries()
        .iter()
        .enumerate()
        .for_each(|(query_index, &(column, at))| {
            circuit_description.fixed_queries.push(Query {
                commitment: format!("f{:?}_commitment", column.index() + 1),
                evaluation: format!("fixedEval{:?}", query_index + 1),
                point: decode(at.0),
            });
        });

    for set in sets.iter() {
        circuit_description.permutation_queries.push(Query {
            commitment: format!("permutations_committed_{}", set),
            evaluation: format!("permutations_evaluated_{}_1", set),
            point: RotationDescription::Current,
        });
        circuit_description.permutation_queries.push(Query {
            commitment: format!("permutations_committed_{}", set),
            evaluation: format!("permutations_evaluated_{}_2", set),
            point: RotationDescription::Next,
        });
    }
    // for all but last
    for set in sets.iter().rev().skip(1) {
        circuit_description.permutation_queries.push(Query {
            commitment: format!("permutations_committed_{}", set),
            evaluation: format!("permutations_evaluated_{}_3", set),
            point: RotationDescription::Last,
        });
    }

    let permutation_common = circuit_description
        .proof_extraction_steps
        .iter()
        .filter(|e| matches!(e, ProofExtractionSteps::PermutationCommon))
        .count();

    (0..permutation_common).for_each(|idx| {
        circuit_description.common_queries.push(Query {
            commitment: format!("p{:?}_commitment", idx + 1),
            evaluation: format!("permutationCommon{:?}", idx + 1),
            point: RotationDescription::Current,
        });
    });

    circuit_description.vanishing_queries.push(Query {
        commitment: "vanishing_g".to_string(),
        evaluation: "vanishing_s".to_string(),
        point: RotationDescription::Current,
    });
    circuit_description.vanishing_queries.push(Query {
        commitment: "vanishingRand".to_string(),
        evaluation: "randomEval".to_string(),
        point: RotationDescription::Current,
    });

    let lookup_commitment_count = circuit_description
        .proof_extraction_steps
        .iter()
        .filter(|e| **e == ProofExtractionSteps::LookupCommitment)
        .collect::<Vec<_>>()
        .len();

    (0..lookup_commitment_count).for_each(|idx| {
        circuit_description.lookup_queries.push(Query {
            commitment: format!("lookupCommitment{:?}", idx + 1),
            evaluation: format!("product_eval_{:?}", idx + 1),
            point: RotationDescription::Current,
        });
        circuit_description.lookup_queries.push(Query {
            commitment: format!("permutedInput{:?}", idx + 1),
            evaluation: format!("permuted_input_eval_{:?}", idx + 1),
            point: RotationDescription::Current,
        });
        circuit_description.lookup_queries.push(Query {
            commitment: format!("permutedTable{:?}", idx + 1),
            evaluation: format!("permuted_table_eval_{:?}", idx + 1),
            point: RotationDescription::Current,
        });
        circuit_description.lookup_queries.push(Query {
            commitment: format!("permutedInput{:?}", idx + 1),
            evaluation: format!("permuted_input_inv_eval_{:?}", idx + 1),
            point: RotationDescription::Previous,
        });
        circuit_description.lookup_queries.push(Query {
            commitment: format!("lookupCommitment{:?}", idx + 1),
            evaluation: format!("product_next_eval_{:?}", idx + 1),
            point: RotationDescription::Next,
        });
    });

    // insert omega extraction
    //todo count all point rotations to get number of omegas
    // default is 3: current, next and last
    // if there are lookups it is 4, additional -1 called inv or previous
    // add cheks for other possible rotations that may appear in equations
    let number_of_omegas = if vk.cs().lookups().is_empty() { 3 } else { 4 };
    let circuit_description = extract_omegas(circuit_description, number_of_omegas);

    let _result = emit_verifier_code(
        verifier_template_file,
        "plutus-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/Verifier.hs".to_string(),
        &circuit_description,
    )
    .map_err(|e| e.to_string())
    .map_err(|_e| Error::Synthesis)?;
    let _result = emit_vk_code(
        vk_template_file,
        "plutus-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/VKConstants.hs".to_string(),
        &circuit_description,
        g2_encoder,
    )
    .map_err(|e| e.to_string())
    .map_err(|_e| Error::Synthesis)?;

    Ok(circuit_description)
}

fn extract_omegas(
    mut circuit_description: CircuitRepresentation,
    number_of_omegas: usize,
) -> CircuitRepresentation {
    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::V);

    circuit_description.instantiation_data.w_values_count = number_of_omegas;
    // witnesses
    for _ in 0..number_of_omegas {
        circuit_description
            .proof_extraction_steps
            .push(ProofExtractionSteps::Witnesses);
    }

    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::U);
    circuit_description
}
