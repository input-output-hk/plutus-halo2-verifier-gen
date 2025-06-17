use crate::code_gen::extraction::data::{
    CircuitRepresentation, ProofExtractionSteps, RotationDescription,
};
use crate::code_gen::extraction::utils::{convert_polynomial, read_n_scalars};
use blake2b_simd::State;
use blstrs::{Bls12, G1Affine, G1Projective, Scalar};
use ff::Field;
use halo2_proofs::halo2curves::group::Curve;
use halo2_proofs::halo2curves::group::prime::PrimeCurveAffine;
use halo2_proofs::plonk::{Any, Error, VerifyingKey};
use halo2_proofs::poly::Rotation;
use halo2_proofs::poly::kzg::KZGCommitmentScheme;
use halo2_proofs::poly::kzg::params::ParamsKZG;
use halo2_proofs::transcript::{CircuitTranscript, Transcript};
use halo2_proofs::utils::arithmetic::compute_inner_product;
use itertools::Itertools;
use log::info;
use std::io::BufWriter;

pub mod data;
mod utils;

type Scheme = KZGCommitmentScheme<Bls12>;

pub fn extract_circuit(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, Scheme>,
    instances: &[&[&[Scalar]]],
    transcript: &mut CircuitTranscript<State>,
) -> Result<CircuitRepresentation, Error> {
    for instances in instances.iter() {
        if instances.len() != vk.cs().num_instance_columns() {
            return Err(Error::InvalidInstances);
        }
    }

    let mut circuit_description: CircuitRepresentation = CircuitRepresentation::default();
    circuit_description.common_queries = vec![];

    let num_proofs = instances.len(); //instance_commitments.len();

    let mut transcript_backup = transcript.clone();

    // Hash verification key into transcript
    vk.hash_into(transcript)?;

    for instance in instances.iter() {
        for instance in instance.iter() {
            for value in instance.iter() {
                transcript.common(value)?;
                info!("writ public input (instance) into the transcript");
                circuit_description.public_inputs += 1;
                info!("{:?}", value);
                info!("--------------------------------");
            }
        }
    }

    // Hash the prover's advice commitments into the transcript and squeeze challenges
    let mut advice_commitments =
        vec![vec![G1Affine::generator(); vk.cs().num_advice_columns()]; num_proofs];
    let mut challenges = vec![Scalar::ZERO; vk.cs().num_challenges()];

    let mut i: i32;

    for current_phase in vk.cs().phases().map(|p| p.0) {
        i = 1;
        for advice_commitments in advice_commitments.iter_mut() {
            for (phase, commitment) in vk
                .cs()
                .advice_column_phase()
                .iter()
                .zip(advice_commitments.iter_mut())
            {
                if current_phase == phase {
                    *commitment = transcript.read::<G1Projective>()?.to_affine();
                    circuit_description
                        .proof_extraction_steps
                        .push(ProofExtractionSteps::AdviceCommitments);
                    i = i + 1;
                }
            }
        }
        for (phase, challenge) in vk.cs().challenge_phase().iter().zip(challenges.iter_mut()) {
            if current_phase == phase {
                *challenge = *transcript.squeeze_challenge();
                circuit_description
                    .proof_extraction_steps
                    .push(ProofExtractionSteps::SqueezeChallange);
            }
        }
    }

    // info!("advice_commitments: {:?}", advice_commitments);
    // info!("challenges: {:?}", challenges);

    // Sample theta challenge for keeping lookup columns linearly independent
    let _theta = transcript.squeeze_challenge();

    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::Theta);

    let lookups_permuted = (0..num_proofs)
        .map(|_| -> Result<Vec<_>, _> {
            // Hash each lookup permuted commitment
            vk.cs()
                .lookups()
                .iter()
                .map(|argument| {
                    circuit_description
                        .proof_extraction_steps
                        .push(ProofExtractionSteps::LookupPermuted);
                    argument.read_permuted_commitments(transcript)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Sample beta challenge
    let _beta = transcript.squeeze_challenge();

    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::Beta);

    // Sample gamma challenge
    let _gamma = transcript.squeeze_challenge();

    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::Gamma);

    let permutations_committed = (0..num_proofs)
        .map(|_| {
            // Hash each permutation product commitment
            let chunk_len = vk.cs_degree - 2;
            let commitment_count = vk.cs().permutation().columns.chunks(chunk_len).len();
            let mut v: Vec<ProofExtractionSteps> = (0..commitment_count)
                .map(|_e| ProofExtractionSteps::PermutationsCommited)
                .collect();
            circuit_description.proof_extraction_steps.append(&mut v);

            vk.cs()
                .permutation()
                .read_product_commitments(vk, transcript)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let lookups_committed = lookups_permuted
        .into_iter()
        .map(|lookups| {
            // Hash each lookup product commitment
            lookups
                .into_iter()
                .map(|lookup| lookup.read_product_commitment(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    lookups_committed.iter().flatten().for_each(|_| {
        circuit_description
            .proof_extraction_steps
            .push(ProofExtractionSteps::LookupCommitment)
    });

    // todo replace with adding the VanishingRand
    // this is done so transcript evaluation proceeds as if it was normally verified
    let _random_poly_commitment = transcript.read()?.to_affine();

    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::VanishingRand);

    // Sample y challenge, which keeps the gates linearly independent.
    let _y = transcript.squeeze_challenge();
    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::YCoordinate);

    // todo replace with adding VanishingSplit vk.get_domain().get_quotient_poly_degree() times
    // this is done so transcript evaluation proceeds as if it was normally verified
    // actual values are dropped but count is used to get info about how many h_commitments should be extracted
    let h_commitments = read_n_scalars(transcript, vk.get_domain().get_quotient_poly_degree())?;

    h_commitments.iter().enumerate().for_each(|_| {
        circuit_description
            .proof_extraction_steps
            .push(ProofExtractionSteps::VanishingSplit);
    });

    // Sample x challenge, which is used to ensure the circuit is
    // satisfied with high probability.
    let x = transcript.squeeze_challenge();
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

    let _instance_evals = {
        // todo check for overflow case
        let xn = x.pow(&[vk.n() as u64, 0, 0, 0]);
        circuit_description.instantiation_data.n_coefficient = vk.n();
        circuit_description.instantiation_data.s_g2 = params.s_g2;
        circuit_description.instantiation_data.omega = vk.get_domain().get_omega().to_string();
        circuit_description.instantiation_data.inverted_omega =
            vk.get_domain().get_omega_inv().to_string();
        circuit_description.instantiation_data.barycentric_weight =
            vk.get_domain().barycentric_weight.to_string();
        circuit_description
            .instantiation_data
            .transcript_representation = vk.transcript_repr().to_string();
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
        let l_i_s = &vk.get_domain().l_i_range(*x, xn, rotations);

        circuit_description
            .instantiation_data
            .omega_rotation_count_for_instances = l_i_s.len();

        instances
            .iter()
            .map(|instances| {
                vk.cs()
                    .instance_queries()
                    .iter()
                    .map(|(column, rotation)| {
                        let instances = instances[column.index()];
                        let offset = (max_rotation - rotation.0) as usize;
                        compute_inner_product(instances, &l_i_s[offset..offset + instances.len()])
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    };

    let advice_evals = (0..num_proofs)
        .map(|_| -> Result<Vec<_>, _> {
            // info!("read advice_evals {:?} times", num_proofs);
            read_n_scalars(transcript, vk.cs().advice_queries().len())
        })
        .collect::<Result<Vec<_>, _>>()?;
    advice_evals.iter().flatten().enumerate().for_each(|_| {
        circuit_description
            .proof_extraction_steps
            .push(ProofExtractionSteps::AdviceEval);
    });
    // info!("advice_evals: {:?}", advice_evals);

    let fixed_evals = read_n_scalars(transcript, vk.cs().fixed_queries().len())?;
    // info!("fixed_evals: {:?}", fixed_evals);
    fixed_evals.iter().enumerate().for_each(|_| {
        circuit_description
            .proof_extraction_steps
            .push(ProofExtractionSteps::FixedEval);
    });

    // extract random eval scalar
    // let _vanishing = vanishing.evaluate_after_x(transcript)?;
    // info!("read scalar for vanishing: {:?}", vanishing);
    circuit_description
        .proof_extraction_steps
        .push(ProofExtractionSteps::RandomEval);

    let permutations_common = vk.permutation().evaluate(transcript)?;
    info!("permutation_common: {:?}", permutations_common);
    permutations_common
        .permutation_evals
        .iter()
        .enumerate()
        .for_each(|_| {
            circuit_description
                .proof_extraction_steps
                .push(ProofExtractionSteps::PermutationCommon);
        });

    let permutations_evaluated = permutations_committed
        .into_iter()
        .map(|permutation| {
            // info!("read permutations_evaluated:");
            permutation.evaluate(transcript)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let letters = ('a'..='z').into_iter();
    permutations_evaluated
        .iter()
        .map(|e| e.sets.iter())
        .flatten()
        .zip(letters)
        .for_each(|(e, letter)| {
            circuit_description
                .proof_extraction_steps
                .push(ProofExtractionSteps::PermutationEval(letter));
            circuit_description
                .proof_extraction_steps
                .push(ProofExtractionSteps::PermutationEval(letter));
            if e.permutation_product_last_eval.is_some() {
                circuit_description
                    .proof_extraction_steps
                    .push(ProofExtractionSteps::PermutationEval(letter));
            }
        });

    let lookups_evaluated = lookups_committed
        .into_iter()
        .map(|lookups| -> Result<Vec<_>, _> {
            lookups
                .into_iter()
                .map(|lookup| lookup.evaluate(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    lookups_evaluated.iter().flatten().for_each(|_| {
        circuit_description
            .proof_extraction_steps
            .push(ProofExtractionSteps::LookupEval)
    });
    // above objects get translated correctly

    // This check ensures the circuit is satisfied so long as the polynomial
    // commitments open to the correct values.

    // x^n
    // todo check for overflow
    let xn = x.pow(&[vk.n() as u64, 0, 0, 0]);

    let blinding_factors = vk.cs().blinding_factors();
    let l_evals = vk
        .get_domain()
        .l_i_range(*x, xn, (-((blinding_factors + 1) as i32))..=0);
    assert_eq!(l_evals.len(), 2 + blinding_factors);
    let _l_last = l_evals[0];
    let _l_blind: Scalar = l_evals[1..(1 + blinding_factors)]
        .iter()
        .fold(Scalar::ZERO, |acc, eval| acc + eval);
    let _l_0 = l_evals[1 + blinding_factors];

    let mut compiled_gates: Vec<_> = vk
        .cs()
        .gates()
        .iter()
        .flat_map(move |gate| {
            gate.polynomials().iter().map(move |poly| {
                let mut buf = BufWriter::new(Vec::new());
                let _ = convert_polynomial(poly, &mut buf);
                let bytes = buf.into_inner().unwrap();
                String::from_utf8(bytes).unwrap()
            })
        })
        .collect();

    // fold expressions for particular lookup
    // initial ACC = ZERO
    // folding : ACC = (acc * theta + eval)
    // where eval is subsequent expressions
    // separate separate for input and for table expression
    let compiled_lookups: Vec<(String, String)> = vk
        .cs()
        .lookups()
        .iter()
        .enumerate()
        .map(|(_id, argument)| {
            let input_expressions: Vec<_> = argument
                .input_expressions()
                .iter()
                .map(|e| {
                    let mut buf = BufWriter::new(Vec::new());
                    let _ = convert_polynomial(e, &mut buf);
                    let bytes = buf.into_inner().unwrap();
                    String::from_utf8(bytes).unwrap()
                })
                .collect();

            let folded_input_expressions = input_expressions
                .iter()
                .fold("scalarZero".to_string(), |acc, eval| {
                    format!("({} * theta + {})", acc, eval)
                });

            let table_expressions: Vec<_> = argument
                .table_expressions()
                .iter()
                .map(|e| {
                    let mut buf = BufWriter::new(Vec::new());
                    let _ = convert_polynomial(e, &mut buf);
                    let bytes = buf.into_inner().unwrap();
                    String::from_utf8(bytes).unwrap()
                })
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

    let t: (Vec<String>, Vec<String>) = compiled_lookups.iter().map(|e| e.clone()).unzip();

    circuit_description.compiled_lookups_equations = t;

    //todo add stages to extract data for final pairing check preparation

    let chunk_len = vk.cs_degree - 2;

    info!("permutations expressions");
    // group to get permutation sets
    let sets: Vec<_> = circuit_description
        .proof_extraction_steps
        .iter()
        .filter(|e| match e {
            ProofExtractionSteps::PermutationEval(_) => true,
            _ => false,
        })
        .chunk_by(|e| match e {
            ProofExtractionSteps::PermutationEval(code) => code,
            _ => &'1',
        })
        .into_iter()
        .map(|(c, _)| c)
        .collect();

    // todo think about errors returned
    let first_set = sets
        .first()
        .ok_or("unable to get first element of the set")
        .map_err(|e| Error::Synthesis)?;
    let last_set = sets
        .last()
        .ok_or("unable to get last element of the set")
        .map_err(|e| Error::Synthesis)?;
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
        .filter(|e| match e {
            ProofExtractionSteps::PermutationCommon => true,
            _ => false,
        })
        .count();

    sets.iter()
        .zip(vk.cs().permutation().columns.chunks(chunk_len))
        // replace with proof extractions permutations_common
        .zip(1..=permutations_common)
        .enumerate()
        .for_each(|(chunk_index, ((set, columns), _))| {
            columns.iter().enumerate().for_each(|(idx, &column)| {
                let permutation_index = (chunk_index * chunk_len) + idx + 1;
                let eval_index = vk.cs().get_any_query_index(column, Rotation::cur()) + 1;
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
                let eval_index = vk.cs().get_any_query_index(column, Rotation::cur()) + 1;
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
        .filter(|e| match e {
            ProofExtractionSteps::VanishingSplit => true,
            _ => false,
        })
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
            let query = format!(
                "MinimalVerifierQuery a{:?} adviceEval{:?}",
                column.index() + 1,
                query_index + 1
            );
            circuit_description
                .advice_queries
                .push((query, decode(at.0)));
        });

    vk.cs()
        .fixed_queries()
        .iter()
        .enumerate()
        .for_each(|(query_index, &(column, at))| {
            let query = format!(
                "MinimalVerifierQuery f{:?}_commitment fixedEval{:?}",
                column.index() + 1,
                query_index + 1
            );
            circuit_description
                .fixed_queries
                .push((query, decode(at.0)));
        });

    for set in sets.iter() {
        circuit_description.permutation_queries.push((
            format!(
                "MinimalVerifierQuery permutations_committed_{} permutations_evaluated_{}_1",
                set, set
            ),
            RotationDescription::Current,
        ));
        circuit_description.permutation_queries.push((
            format!(
                "MinimalVerifierQuery permutations_committed_{} permutations_evaluated_{}_2",
                set, set
            ),
            RotationDescription::Next,
        ));
    }
    // for all but last
    for set in sets.iter().rev().skip(1) {
        circuit_description.permutation_queries.push((
            format!(
                "MinimalVerifierQuery permutations_committed_{} permutations_evaluated_{}_3",
                set, set
            ),
            RotationDescription::Last,
        ));
    }

    let permutation_common = circuit_description
        .proof_extraction_steps
        .iter()
        .filter(|e| match e {
            ProofExtractionSteps::PermutationCommon => true,
            _ => false,
        })
        .count();

    (0..permutation_common).for_each(|idx| {
        circuit_description.common_queries.push((
            format!(
                "MinimalVerifierQuery p{:?}_commitment permutationCommon{:?}",
                idx + 1,
                idx + 1
            ),
            RotationDescription::Current,
        ));
    });

    circuit_description.vanishing_queries.push((
        "MinimalVerifierQuery vanishing_g vanishing_s".to_string(),
        RotationDescription::Current,
    ));
    circuit_description.vanishing_queries.push((
        "MinimalVerifierQuery vanishingRand randomEval".to_string(),
        RotationDescription::Current,
    ));

    let lookup_commitment_count = circuit_description
        .proof_extraction_steps
        .iter()
        .filter(|e| **e == ProofExtractionSteps::LookupCommitment)
        .collect::<Vec<_>>()
        .len();

    (0..lookup_commitment_count).for_each(|idx| {
        circuit_description.lookup_queries.push((
            format!(
                "MinimalVerifierQuery lookupCommitment{:?} product_eval_{:?}",
                idx + 1,
                idx + 1
            ),
            RotationDescription::Current,
        ));
        circuit_description.lookup_queries.push((
            format!(
                "MinimalVerifierQuery permutedInput{:?} permuted_input_eval_{:?}",
                idx + 1,
                idx + 1
            ),
            RotationDescription::Current,
        ));
        circuit_description.lookup_queries.push((
            format!(
                "MinimalVerifierQuery permutedTable{:?} permuted_table_eval_{:?}",
                idx + 1,
                idx + 1
            ),
            RotationDescription::Current,
        ));
        circuit_description.lookup_queries.push((
            format!(
                "MinimalVerifierQuery permutedInput{:?} permuted_input_inv_eval_{:?}",
                idx + 1,
                idx + 1
            ),
            RotationDescription::Previous,
        ));
        circuit_description.lookup_queries.push((
            format!(
                "MinimalVerifierQuery lookupCommitment{:?} product_next_eval_{:?}",
                idx + 1,
                idx + 1
            ),
            RotationDescription::Next,
        ));
    });

    Ok(circuit_description)
}
