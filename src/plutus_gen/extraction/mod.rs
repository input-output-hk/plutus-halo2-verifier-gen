//! Module for extracting the steps and data necessary to verify a Halo2 proof.
//! We made the arbitrary choice to implement the `extract_circuit` function in
//! this file as this is the main function to be used outside the library and
//! for ease of reading.

use anyhow::{Error, anyhow};
use midnight_curves::{Bls12, BlsScalar as Scalar, G1Projective};

use midnight_proofs::plonk::VerifyingKey;
use midnight_proofs::poly::commitment::PolynomialCommitmentScheme;
use midnight_proofs::poly::kzg::params::ParamsKZG;

#[cfg(feature = "plutus_debug")]
use log::info;

pub(crate) mod data;
pub use data::CircuitRepresentation;
use data::{
    Commitments, Evaluations, RotationDescription,
    extraction_steps::{
        evaluate_permutations_terms, extract_proof_steps, permutation_terms_both,
        vanishing_expressions,
    },
};

pub(crate) mod pcs;
pub use pcs::ExtractPCS;

/// Function extracting the circuit description from a verification key,
/// parameters and instance.
pub fn extract_circuit<PCS>(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, PCS>,
    recursion_vks: Option<Vec<(String, VerifyingKey<Scalar, PCS>)>>, // Set to Some if recursion, filled with inner vks only
    instance: &[Scalar],
    committed_instances: Option<G1Projective>,
) -> Result<CircuitRepresentation<PCS>, Error>
where
    PCS: ExtractPCS + PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
    let mut nb_committed_instances = 0;
    if committed_instances.is_some() {
        nb_committed_instances = 1;
    }

    // Checking that the number of committed instances and public inputs equal
    // the number of instance columns.
    if nb_committed_instances + 1 != vk.cs().num_instance_columns() {
        return Err(anyhow!(
            "Invalid number of (committed) instances, #committed instance ({}) + #instances ({}) != #instance_columns ({})",
            nb_committed_instances,
            instance.len(),
            vk.cs().num_instance_columns()
        ));
    }

    let chunk_len = vk.cs().degree() - 2;

    let mut circuit_description: CircuitRepresentation<PCS> = CircuitRepresentation::<PCS>::new();

    // Extracting proof_instantiation_data
    circuit_description.proof_instantiation_data.extract(
        params,
        vk,
        recursion_vks,
        instance,
        committed_instances,
    );

    // Extracting proof_extraction_steps
    extract_proof_steps(&mut circuit_description, vk);

    let sets = circuit_description.compute_sets();
    let nb_permutation_common = circuit_description.nb_permutation_common();
    let nb_lookup_commitments = circuit_description.nb_lookup_commitments();

    #[cfg(feature = "plutus_debug")]
    info!("---- Extracting expressions");
    {
        // Extracting compiled_gate_equations
        vk.cs().gates().iter().for_each(|gate| {
            gate.polynomials().iter().for_each(|poly| {
                circuit_description.expressions.gate(poly.clone());
            })
        });

        // Extracting compiled_lookups_equations
        vk.cs().lookups().iter().for_each(|argument| {
            let inputs = argument.input_expressions().to_vec();
            let tables = argument.table_expressions().to_vec();
            circuit_description.expressions.lookup(inputs, tables);
        });

        // Extracting compiled_trashcans expressions
        vk.cs().trashcans().iter().for_each(|argument| {
            let name = argument.name().to_string();
            let selector = argument.selector().clone();
            let expression = argument.constraint_expressions().to_vec();
            circuit_description
                .expressions
                .trashcan(name, selector, expression);
        });

        // Extracting permutations_evaluated_terms
        evaluate_permutations_terms(&mut circuit_description, &sets);

        // Extracting permutation_terms_left and permutation_terms_right
        permutation_terms_both(
            &mut circuit_description,
            vk,
            chunk_len,
            &sets,
            nb_permutation_common,
        );

        // Extracting h_commitments
        vanishing_expressions(&mut circuit_description);
    }

    #[cfg(feature = "plutus_debug")]
    info!("---- Extracting queries");
    {
        // Extracting instance queries
        vk.cs()
            .instance_queries()
            .iter()
            .enumerate()
            .for_each(|(query_index, &(column, at))| {
                // Only extracting instance queries for committed instances
                if column.index()
                    < circuit_description
                        .proof_instantiation_data
                        .committed_instances_count
                {
                    circuit_description
                        .queries
                        .instance(column.index() + 1, query_index + 1, at.0);
                }
            });

        // Extracting advice queries
        vk.cs()
            .advice_queries()
            .iter()
            .enumerate()
            .for_each(|(query_index, &(column, at))| {
                circuit_description
                    .queries
                    .advice(column.index() + 1, query_index + 1, at.0);
            });

        // Extracting fixed queries
        vk.cs()
            .fixed_queries()
            .iter()
            .enumerate()
            .for_each(|(query_index, &(column, at))| {
                circuit_description
                    .queries
                    .fixed(column.index() + 1, query_index + 1, at.0);
            });

        // Extracting permutation queries
        // /!\ the ordering of the queries is important, as changing it may
        // /!\ break the verifier by disssociating the variables names from
        // /!\ their use.
        for set in sets.iter() {
            circuit_description
                .queries
                .permutation(*set, 1, RotationDescription::Current);
            circuit_description
                .queries
                .permutation(*set, 2, RotationDescription::Next);
        }
        for set in sets.iter().rev().skip(1) {
            circuit_description
                .queries
                .permutation(*set, 3, RotationDescription::Last);
        }

        // Extracting (permutation) common queries
        (0..nb_permutation_common).for_each(|idx| {
            circuit_description.queries.common(idx + 1);
        });

        // Extracting vanishing queries
        circuit_description.queries.vanishing_queries();

        // Extracting lookup queries
        (0..nb_lookup_commitments).for_each(|idx| {
            circuit_description.queries.lookup(
                Commitments::Lookup(idx + 1), //format!("lookupCommitment{:?}", idx + 1),
                Evaluations::Lookup(idx + 1), //format!("product_eval_{:?}", idx + 1),
                RotationDescription::Current,
            );
            circuit_description.queries.lookup(
                Commitments::PermutedInput(idx + 1), //format!("permutedInput{:?}", idx + 1),
                Evaluations::PermutedInput(idx + 1), //format!("permuted_input_eval_{:?}", idx + 1),
                RotationDescription::Current,
            );
            circuit_description.queries.lookup(
                Commitments::PermutedTable(idx + 1), //format!("permutedTable{:?}", idx + 1),
                Evaluations::PermutedTable(idx + 1), //format!("permuted_table_eval_{:?}", idx + 1),
                RotationDescription::Current,
            );
            circuit_description.queries.lookup(
                Commitments::PermutedInput(idx + 1), //format!("permutedInput{:?}", idx + 1),
                Evaluations::PermutedInputInverse(idx + 1), //format!("permuted_input_inv_eval_{:?}", idx + 1),
                RotationDescription::Previous,
            );
            circuit_description.queries.lookup(
                Commitments::Lookup(idx + 1), //format!("lookupCommitment{:?}", idx + 1),
                Evaluations::LookupNext(idx + 1), //format!("product_next_eval_{:?}", idx + 1),
                RotationDescription::Next,
            );
        });

        // Extracting trashcan queries
        vk.cs()
            .trashcans()
            .iter()
            .enumerate()
            .for_each(|(query_index, _arg)| {
                circuit_description.queries.trashcan(query_index + 1);
            });
    }

    // Extracting PCS steps
    PCS::extract_pcs(&mut circuit_description);

    Ok(circuit_description)
}
