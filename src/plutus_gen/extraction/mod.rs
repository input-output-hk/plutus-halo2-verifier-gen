use midnight_curves::{Bls12, BlsScalar as Scalar, G1Projective};
use midnight_proofs::plonk::{Error, VerifyingKey};
use midnight_proofs::poly::commitment::PolynomialCommitmentScheme;
use midnight_proofs::poly::kzg::params::ParamsKZG;

use log::debug;
#[cfg(feature = "plutus_debug")]
use log::info;

pub mod data;
pub use data::*;

pub(crate) mod pcs;

impl CircuitRepresentation {
    pub fn extract_circuit<S>(
        params: &ParamsKZG<Bls12>,
        vk: &VerifyingKey<Scalar, S>,
        instances: &[&[&[Scalar]]],
    ) -> Result<Self, Error>
    where
        S: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
    {
        let chunk_len = vk.cs().degree() - 2;

        #[cfg(feature = "plutus_debug")]
        info!("Following Midnight-zk's parse_trace function");

        for instances in instances.iter() {
            if instances.len() != vk.cs().num_instance_columns() {
                return Err(Error::InvalidInstances);
            }
        }

        // We suppose we only are verifying a single proof
        if instances.len() > 1 {
            panic!("More than 1 proof for processing");
        }

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

        let mut circuit_description: CircuitRepresentation = CircuitRepresentation::default();

        // Extracting instantiation_data
        circuit_description.extract_instantiation_data(params, vk, instances, rotations.len());

        // Extracting (number of) public_inputs
        for instance in instances.iter() {
            for instance in instance.iter() {
                for value in instance.iter() {
                    // transcript.common(value)?;
                    debug!("write public input (instance) into the transcript");
                    circuit_description.public_inputs += 1;
                    debug!("{:?}", value);
                    debug!("--------------------------------");
                }
            }
        }

        // Extracting proof_extraction_steps
        circuit_description.extract_proof_steps(vk);

        let sets = circuit_description.compute_sets();
        let sets_len = sets.len();

        let nb_permutation_common = circuit_description.nb_permutation_common();
        let nb_lookup_commitments = circuit_description.nb_lookup_commitments();

        debug!("---- Extracting expressions");
        {
            // Extracting compiled_gate_equations
            vk.cs().gates().iter().for_each(|gate| {
                gate.polynomials().iter().for_each(|poly| {
                    circuit_description.gate_expression(poly.clone());
                })
            });

            // Extracting compiled_lookups_equations
            vk.cs().lookups().iter().for_each(|argument| {
                let inputs = argument.input_expressions().to_vec();
                let tables = argument.table_expressions().to_vec();
                circuit_description.lookup_expression(inputs, tables);
            });

            // Extracting permutations_evaluated_terms
            let expressions = evaluate_permutations_terms(&sets).unwrap();
            for expression in expressions {
                circuit_description.permutation_eval_expression(expression);
            }

            // Extracting permutation_terms_left and permutation_terms_right
            let (terms_left, terms_right) =
                permutation_terms_both(&vk, chunk_len, &sets, nb_permutation_common).unwrap();

            for (index, expression) in terms_left {
                circuit_description.permutation_left_expression(index, expression);
            }
            for (index, expression) in terms_right {
                circuit_description.permutation_right_expression(index, expression);
            }

            // Extracting h_commitments
            let vanishing_terms = vanishing_expressions(&circuit_description);
            for (name, expression) in vanishing_terms {
                circuit_description.vanishing_expression(name, expression);
            }

            // Extracting compiled_trashcans
            vk.cs().trashcans().iter().for_each(|argument| {
                let name = argument.name().to_string();
                let selector = argument.selector().clone();
                let expressions = argument.constraint_expressions().to_vec();
                // (name, selector, expressions)
                circuit_description.trashcan_expression(name, selector, expressions);
            });
        }

        debug!("---- Extracting queries");
        {
            // Extracting advice_queries
            vk.cs()
                .advice_queries()
                .iter()
                .enumerate()
                .for_each(|(query_index, &(column, at))| {
                    circuit_description.advice_query(
                        Commitments::Advice(column.index() + 1), //format!("a{:?}", column.index() + 1),
                        Evaluations::Advice(query_index + 1), //format!("adviceEval{:?}", query_index + 1),
                        RotationDescription::from_i32(at.0),
                    );
                });

            // Extracting fixed_queries
            vk.cs()
                .fixed_queries()
                .iter()
                .enumerate()
                .for_each(|(query_index, &(column, at))| {
                    circuit_description.fixed_query(
                        Commitments::Fixed(column.index() + 1), //format!("f{:?}_commitment", column.index() + 1),
                        Evaluations::Fixed(query_index + 1), //format!("fixedEval{:?}", query_index + 1),
                        RotationDescription::from_i32(at.0),
                    );
                });

            // Extracting permutation_queries (for current, next and last rotations)
            for (i, set) in sets.into_iter().enumerate() {
                circuit_description.permutation_query(
                    Commitments::Permutation(set), //format!("permutations_committed_{}", set),
                    Evaluations::Permutation(set, 1), //format!("permutations_evaluated_{}_1", set),
                    RotationDescription::Current,
                );
                circuit_description.permutation_query(
                    Commitments::Permutation(set), //format!("permutations_committed_{}", set),
                    Evaluations::Permutation(set, 2), //format!("permutations_evaluated_{}_2", set),
                    RotationDescription::Next,
                );

                if i != sets_len - 1 {
                    circuit_description.permutation_query(
                        Commitments::Permutation(set), //format!("permutations_committed_{}", set),
                        Evaluations::Permutation(set, 3), //format!("permutations_evaluated_{}_3", set),
                        RotationDescription::Last,
                    );
                }
            }

            // Extracting (permutation) common_queries
            (0..nb_permutation_common).for_each(|idx| {
                circuit_description.common_query(
                    Commitments::PermutationsCommon(idx + 1), //format!("p{:?}_commitment", idx + 1),
                    Evaluations::PermutationsCommon(idx + 1), //format!("permutationCommon{:?}", idx + 1),
                    RotationDescription::Current,
                );
            });

            // Extracting vanishing_queries
            circuit_description.vanishing_query(
                Commitments::VanishingG, //"vanishing_g".to_string(),
                Evaluations::VanishingS, //"vanishing_s".to_string(),
                RotationDescription::Current,
            );
            circuit_description.vanishing_query(
                Commitments::VanishingRand, //"vanishingRand".to_string(),
                Evaluations::RandomEval,    //"randomEval".to_string(),
                RotationDescription::Current,
            );

            // Extracting lookup_queries
            (0..nb_lookup_commitments).for_each(|idx| {
                circuit_description.lookup_query(
                    Commitments::Lookup(idx + 1), //format!("lookupCommitment{:?}", idx + 1),
                    Evaluations::Lookup(idx + 1), //format!("product_eval_{:?}", idx + 1),
                    RotationDescription::Current,
                );
                circuit_description.lookup_query(
                    Commitments::PermutedInput(idx + 1), //format!("permutedInput{:?}", idx + 1),
                    Evaluations::PermutedInput(idx + 1), //format!("permuted_input_eval_{:?}", idx + 1),
                    RotationDescription::Current,
                );
                circuit_description.lookup_query(
                    Commitments::PermutedTable(idx + 1), //format!("permutedTable{:?}", idx + 1),
                    Evaluations::PermutedTable(idx + 1), //format!("permuted_table_eval_{:?}", idx + 1),
                    RotationDescription::Current,
                );
                circuit_description.lookup_query(
                    Commitments::PermutedInput(idx + 1), //format!("permutedInput{:?}", idx + 1),
                    Evaluations::PermutedInputInverse(idx + 1), //format!("permuted_input_inv_eval_{:?}", idx + 1),
                    RotationDescription::Previous,
                );
                circuit_description.lookup_query(
                    Commitments::Lookup(idx + 1), //format!("lookupCommitment{:?}", idx + 1),
                    Evaluations::LookupNext(idx + 1), //format!("product_next_eval_{:?}", idx + 1),
                    RotationDescription::Next,
                );
            });
        }

        Ok(circuit_description)
    }
}
