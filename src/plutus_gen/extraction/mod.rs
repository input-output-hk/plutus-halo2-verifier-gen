use crate::plutus_gen::extraction::data::{
    CircuitRepresentation, CommitmentData, ProofExtractionSteps, Query, RotationDescription,
};
use crate::plutus_gen::extraction::utils::{compile_expressions, get_any_query_index};
use blstrs::{Bls12, G1Affine, G1Projective, Scalar};
use ff::Field;
use halo2_proofs::halo2curves::group::Curve;
use halo2_proofs::halo2curves::group::prime::PrimeCurveAffine;
use halo2_proofs::plonk::{Any, Error, VerifyingKey};
use halo2_proofs::poly::commitment::PolynomialCommitmentScheme;
use halo2_proofs::poly::{
    Rotation, gwc_kzg::GwcKZGCommitmentScheme, kzg::KZGCommitmentScheme, kzg::params::ParamsKZG,
};
use itertools::Itertools;
use log::debug;
use std::collections::HashMap;

pub mod data;
mod utils;

type GWC19Scheme = GwcKZGCommitmentScheme<Bls12>;
type Halo2MultiOpenScheme = KZGCommitmentScheme<Bls12>;

pub enum KzgType {
    GWC19,
    Halo2MultiOpen,
}

pub trait ExtractKZG {
    fn extract_kzg_steps(circuit_representation: CircuitRepresentation) -> CircuitRepresentation;
    fn kzg_type() -> KzgType;
}

impl ExtractKZG for GWC19Scheme {
    fn extract_kzg_steps(
        mut circuit_representation: CircuitRepresentation,
    ) -> CircuitRepresentation {
        circuit_representation
            .proof_extraction_steps
            .push(ProofExtractionSteps::V);

        // todo double check if number of final witnesses is equal to number of different X rotations
        let number_of_witnesses = circuit_representation
            .all_queries_ordered()
            .iter()
            .flatten()
            .map(|q| q.point.clone())
            .unique()
            .count();

        circuit_representation.instantiation_data.w_values_count = number_of_witnesses;
        // witnesses
        for _ in 0..number_of_witnesses {
            circuit_representation
                .proof_extraction_steps
                .push(ProofExtractionSteps::Witnesses);
        }

        circuit_representation
            .proof_extraction_steps
            .push(ProofExtractionSteps::U);
        circuit_representation
    }

    fn kzg_type() -> KzgType {
        KzgType::GWC19
    }
}

impl ExtractKZG for Halo2MultiOpenScheme {
    fn extract_kzg_steps(
        mut circuit_representation: CircuitRepresentation,
    ) -> CircuitRepresentation {
        // sample 2 squeeze challenges x1 x2
        // read f commitment to transcript
        // sample 1 squeeze challenges x3
        // read all q polly evaluations - this is length of point sets list
        // sample 1 squeeze challenges x4
        // read pi g1 element

        circuit_representation
            .proof_extraction_steps
            .push(ProofExtractionSteps::X1);

        circuit_representation
            .proof_extraction_steps
            .push(ProofExtractionSteps::X2);

        circuit_representation
            .proof_extraction_steps
            .push(ProofExtractionSteps::FCommitment);

        circuit_representation
            .proof_extraction_steps
            .push(ProofExtractionSteps::X3);

        // number of final witnesses is equal to number of different point sets
        let (sets, _) = precompute_intermediate_sets(&circuit_representation);
        let number_of_witnesses = sets.len();

        circuit_representation
            .instantiation_data
            .q_evaluations_count = number_of_witnesses;
        // witnesses
        for _ in 0..number_of_witnesses {
            circuit_representation
                .proof_extraction_steps
                .push(ProofExtractionSteps::QEvals);
        }

        circuit_representation
            .proof_extraction_steps
            .push(ProofExtractionSteps::X4);

        circuit_representation
            .proof_extraction_steps
            .push(ProofExtractionSteps::PI);

        circuit_representation
    }

    fn kzg_type() -> KzgType {
        KzgType::Halo2MultiOpen
    }
}

pub fn extract_circuit<S>(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, S>,
    instances: &[&[&[Scalar]]],
) -> Result<CircuitRepresentation, Error>
where
    S: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
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
                debug!("writ public input (instance) into the transcript");
                circuit_description.public_inputs += 1;
                debug!("{:?}", value);
                debug!("--------------------------------");
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

    debug!("permutations expressions");
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

    /// this function handles only 3 types of rotations,
    /// this is done to reduce number of scalars that have to be on the plutus side
    fn decode(input: i32) -> RotationDescription {
        match input {
            -1 => RotationDescription::Previous,
            0 => RotationDescription::Current,
            1 => RotationDescription::Next,
            _ => panic!(
                "unknown number {} for rotation, only -1 0 and 1 are supported",
                input
            ),
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

    Ok(circuit_description)
}

pub fn precompute_intermediate_sets(
    circuit_description: &CircuitRepresentation,
) -> (Vec<Vec<RotationDescription>>, Vec<CommitmentData>) {
    let queries = circuit_description.all_queries_ordered();

    let ordered_unique_commitments: Vec<String> = queries
        .iter()
        .flatten()
        .map(|q| &q.commitment)
        .cloned()
        .unique()
        .collect();

    let commitment_map: HashMap<String, _> = queries
        .iter()
        .flatten()
        .into_group_map_by(|e| e.commitment.clone());

    let point_sets_map: HashMap<String, Vec<RotationDescription>> = commitment_map
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                v.iter()
                    .map(|e| &e.point)
                    .cloned()
                    .unique()
                    .collect::<Vec<_>>(),
            )
        })
        .collect();

    let mut grouped_points: Vec<Vec<RotationDescription>> = vec![];

    for commitment in ordered_unique_commitments.iter() {
        grouped_points.push(point_sets_map.get(commitment).unwrap().clone());
    }

    let unique_grouped_points: Vec<Vec<_>> = grouped_points.iter().cloned().unique().collect();

    let point_sets_indexes: HashMap<_, _> = unique_grouped_points
        .iter()
        .enumerate()
        .map(|(a, b)| (b.clone(), a))
        .collect();

    let mut commitment_data: Vec<CommitmentData> = vec![];

    for commitment in ordered_unique_commitments.iter() {
        let query = commitment_map.get(commitment).unwrap();
        let points: Vec<RotationDescription> = query.iter().map(|q| q.point.clone()).collect();

        let point_set_idx = point_sets_indexes.get(&points).unwrap();

        commitment_data.push(CommitmentData {
            commitment: (*commitment).clone(),
            point_set_index: *point_set_idx,
            evaluations: query.iter().map(|q| q.evaluation.clone()).collect(),
            points,
        });
    }
    (unique_grouped_points, commitment_data)
}
