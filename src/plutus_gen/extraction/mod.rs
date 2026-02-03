use blstrs::{Bls12, G1Projective, Scalar};

use halo2_proofs::plonk::{Error, VerifyingKey};
use halo2_proofs::poly::commitment::PolynomialCommitmentScheme;
use halo2_proofs::poly::kzg::params::ParamsKZG;

use log::debug;
#[cfg(feature = "plutus_debug")]
use log::info;

pub mod data;
pub use data::*;

pub(crate) mod pcs;

impl CircuitRepresentation {
    fn rotations<S>(vk: &VerifyingKey<Scalar, S>) -> (i32, i32)
    where
        S: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
    {
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
            })
    }

    fn instance_max_length<S>(instances: &[&[&[Scalar]]]) -> usize
    where
        S: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
    {
        instances
            .iter()
            .flat_map(|instance| instance.iter().map(|instance| instance.len()))
            .max_by(Ord::cmp)
            .unwrap_or_default()
    }

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

        let mut circuit_description: CircuitRepresentation = CircuitRepresentation::default();

        // Extracting instantiation_data
        let (min_rotation, max_rotation) = Self::rotations::<S>(vk);
        let max_instance_len = Self::instance_max_length::<S>(instances) as i32;
        let rotations = -max_rotation..max_instance_len + min_rotation.abs();
        circuit_description.extract_instantiation_data(params, vk, instances, rotations.len());

        // Extracting (number of) public_inputs
        for instance in instances.iter() {
            for instance in instance.iter() {
                for value in instance.iter() {
                    // transcript.common(value)?;
                    debug!("write public input (instance) into the transcript");
                    circuit_description.increment_public_inputs();
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
        }

        debug!("---- Extracting queries");
        {
            // Extracting advice_queries
            vk.cs()
                .advice_queries()
                .iter()
                .enumerate()
                .for_each(|(query_index, &(column, at))| {
                    circuit_description.advice_query(column.index() + 1, query_index + 1, at.0);
                });

            // Extracting fixed_queries
            vk.cs()
                .fixed_queries()
                .iter()
                .enumerate()
                .for_each(|(query_index, &(column, at))| {
                    circuit_description.fixed_query(column.index() + 1, query_index + 1, at.0);
                });

            // Extracting permutation_queries (for current, next and last rotations)
            for (i, set) in sets.into_iter().enumerate() {
                circuit_description.permutation_query(set, 1, RotationDescription::Current);
                circuit_description.permutation_query(set, 2, RotationDescription::Next);

                if i != sets_len - 1 {
                    circuit_description.permutation_query(set, 3, RotationDescription::Last);
                }
            }

            // Extracting (permutation) common_queries
            (0..nb_permutation_common).for_each(|idx| {
                circuit_description.common_query(idx + 1);
            });

            // Extracting vanishing_queries
            circuit_description.vanishing_queries();

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
