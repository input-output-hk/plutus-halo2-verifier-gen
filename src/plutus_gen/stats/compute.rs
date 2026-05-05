//! Exact verifier cost computation from a fully extracted `CircuitRepresentation`.
use blstrs::{G1Projective, Scalar};
use halo2_proofs::{
    plonk::VerifyingKey, poly::commitment::PolynomialCommitmentScheme, utils::SerdeFormat,
};
use itertools::Itertools;
use std::collections::HashMap;

use crate::plutus_gen::extraction::data::{CircuitRepresentation, ProofExtractionSteps};
use crate::plutus_gen::extraction::pcs::{ExtractPCS, PCSType};

use super::circuit_statistics::CircuitStatistics;
use super::pcs::gwc19::{construct_msm, group_queries_by_point};

/// Computes the exact verifier operation counts for a circuit whose representation has
/// already been fully extracted. Use `estimate_verifier_code` when no circuit is available.
pub fn compute_verifier_code<PCS>(
    vk: &VerifyingKey<Scalar, PCS>,
    circuit: &CircuitRepresentation<PCS>,
) -> CircuitStatistics
where
    PCS: ExtractPCS + PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
    let size_proof = {
        let (pes_commitments, pes_scalars) =
            circuit
                .proof_extraction_steps
                .iter()
                .fold((0, 0), |acc, pes| {
                    let (c, s) = pes.step_stat();
                    (acc.0 + c, acc.1 + s)
                });
        let (pcs_commitments, pcs_scalars) =
            circuit
                .pcs_extraction_steps
                .iter()
                .fold((0, 0), |acc, step| {
                    let (c, s) = PCS::step_stat(step);
                    (acc.0 + c, acc.1 + s)
                });
        (pes_commitments + pcs_commitments) * 48 + (pes_scalars + pcs_scalars) * 32
    };

    let mut stats = CircuitStatistics::new(
        size_proof,
        vk.bytes_length(SerdeFormat::Processed),
        circuit.proof_instantiation_data.public_inputs_count,
    );

    let bf = circuit.proof_instantiation_data.blinding_factors;
    let nb_pis = circuit.proof_instantiation_data.public_inputs_count;

    // Rotations for vanishing polynomial
    (0..=bf).for_each(|_| stats.rotate_omega());

    // Absorb vk, public-input count, and each PI value
    stats.common_scalar();
    stats.common_scalar();
    stats.from_int_scalar();
    (0..nb_pis).for_each(|_| stats.common_scalar());

    // Proof extraction steps (commitments, challenges, scalars)
    circuit
        .proof_extraction_steps
        .iter()
        .chunk_by(|e| (*e).clone())
        .into_iter()
        .for_each(|(step, group)| match step {
            ProofExtractionSteps::AdviceCommitments => group.for_each(|_| stats.read_point()),
            ProofExtractionSteps::Theta => stats.squeeze_challenge(),
            ProofExtractionSteps::Beta => stats.squeeze_challenge(),
            ProofExtractionSteps::Gamma => stats.squeeze_challenge(),
            ProofExtractionSteps::PermutationsCommitted => group.for_each(|_| stats.read_point()),
            ProofExtractionSteps::VanishingRand => group.for_each(|_| stats.read_point()),
            ProofExtractionSteps::YCoordinate => stats.squeeze_challenge(),
            ProofExtractionSteps::VanishingSplit => group.for_each(|_| stats.read_point()),
            ProofExtractionSteps::XCoordinate => stats.squeeze_challenge(),
            ProofExtractionSteps::AdviceEval => group.for_each(|_| stats.read_scalar()),
            ProofExtractionSteps::FixedEval => group.for_each(|_| stats.read_scalar()),
            ProofExtractionSteps::RandomEval => stats.read_scalar(),
            ProofExtractionSteps::PermutationCommon => group.for_each(|_| stats.read_scalar()),
            ProofExtractionSteps::PermutationEval(_) => group.for_each(|_| stats.read_scalar()),
            ProofExtractionSteps::LookupPermuted => group.for_each(|_| {
                stats.read_point();
                stats.read_point();
            }),
            ProofExtractionSteps::LookupCommitment => group.for_each(|_| stats.read_point()),
            ProofExtractionSteps::LookupEval => group.for_each(|_| {
                stats.read_scalar();
                stats.read_scalar();
                stats.read_scalar();
                stats.read_scalar();
                stats.read_scalar();
            }),
            ProofExtractionSteps::SqueezeChallenge => panic!("unexpected SqueezeChallenge in PES"),
        });

    circuit
        .pcs_extraction_steps
        .iter()
        .for_each(|step| PCS::step_stat_operation(&mut stats, step));

    assert_eq!(stats.transcript_size, 0);

    // Evaluation point setup
    stats.pow_scalar(); // x^n
    stats.rotate_omega(); // x_prev
    stats.rotate_omega(); // x_current
    stats.rotate_omega(); // x_next
    stats.rotate_omega(); // x_last

    // Lagrange bases and active-rows scalar for blinding factors
    stats.lagrange_polynomial_basis(1 + bf);
    (1..=bf).for_each(|_| stats.add_scalar());
    stats.add_scalar();
    stats.sub_scalar();

    // Lagrange basis and inner product for public inputs
    (1..=nb_pis).for_each(|_| stats.rotate_omega());
    stats.lagrange_polynomial_basis(nb_pis);
    stats.inner_product(nb_pis);

    // Gate equations
    circuit
        .expressions
        .compiled_gate_equations
        .iter()
        .for_each(|gate| stats.expression(gate));

    // Lookup input/table expression folding
    for input_lookups in circuit.expressions.compiled_lookups_equations.0.iter() {
        for lookup in input_lookups {
            stats.add_scalar();
            stats.mul_scalar();
            stats.expression(lookup);
        }
    }
    for table_lookups in circuit.expressions.compiled_lookups_equations.1.iter() {
        for lookup in table_lookups {
            stats.add_scalar();
            stats.mul_scalar();
            stats.expression(lookup);
        }
    }

    // Lookup constraint equations (fixed structure per lookup)
    let nb_lookups = circuit.expressions.compiled_lookups_equations.0.len();
    (0..nb_lookups).for_each(|_| {
        stats.sub_scalar(); // l1: 1 - product_eval
        stats.mul_scalar();
        stats.mul_scalar(); // l2: product_eval²
        stats.sub_scalar();
        stats.mul_scalar();
        stats.add_scalar(); // lookup_left: + beta
        stats.add_scalar(); //              + gamma
        stats.mul_scalar();
        stats.mul_scalar();
        stats.add_scalar(); // lookup_right: + beta
        stats.add_scalar(); //               + gamma
        stats.mul_scalar();
        stats.mul_scalar();
        stats.sub_scalar(); // l3: left - right
        stats.mul_scalar(); //     * active_rows
        stats.sub_scalar(); // l4
        stats.mul_scalar();
        stats.sub_scalar(); // l5
        stats.mul_scalar();
        stats.sub_scalar();
        stats.mul_scalar();
    });

    // Permutation evaluated terms
    circuit
        .expressions
        .permutations_evaluated_terms
        .iter()
        .for_each(|exp| stats.scalar_expression(exp));

    // Permutation left terms (grouped by set, then batched)
    let mut sets_lhs: HashMap<char, ()> = HashMap::new();
    for (set, exp) in &circuit.expressions.permutation_terms_left {
        if sets_lhs.contains_key(set) {
            stats.mul_scalar();
        } else {
            sets_lhs.insert(*set, ());
        }
        stats.scalar_expression(exp);
    }
    sets_lhs.iter().for_each(|_| stats.mul_scalar());

    // Permutation right terms
    let mut sets_rhs: HashMap<char, ()> = HashMap::new();
    for (set, exp) in &circuit.expressions.permutation_terms_right {
        if sets_rhs.contains_key(set) {
            stats.mul_scalar();
        } else {
            sets_rhs.insert(*set, ());
        }
        stats.scalar_expression(exp);
    }
    sets_rhs.iter().for_each(|_| stats.mul_scalar());

    // Combine left and right permutation sets
    assert_eq!(sets_lhs.len(), sets_rhs.len());
    (0..sets_lhs.len()).for_each(|_| {
        stats.mul_scalar();
        stats.sub_scalar();
        stats.sub_scalar();
        stats.add_scalar();
    });

    // Expressions combiner
    let total_expressions = circuit.expressions.compiled_gate_equations.len()
        + circuit.expressions.permutations_evaluated_terms.len()
        + sets_lhs.len()
        + circuit.expressions.compiled_lookups_equations.0.len() * 5;
    (0..total_expressions).for_each(|_| {
        stats.add_scalar();
        stats.mul_scalar();
    });

    // Vanishing check
    stats.sub_scalar();
    stats.inv_scalar();
    stats.mul_scalar();

    circuit
        .expressions
        .h_commitments
        .iter()
        .for_each(|(_, exp)| stats.point_expression(exp));

    stats.compress_point();

    // PCS-specific post-computation
    let (unique_points, commitment_data) = PCS::precompute_intermediate_sets(circuit);

    if PCS::pcs_type() == PCSType::Halo2MultiOpen {
        let num_point_sets = unique_points.len();
        let max_per_set = (0..num_point_sets)
            .map(|idx| {
                commitment_data
                    .iter()
                    .filter(|cd| cd.point_set_index == idx)
                    .count()
            })
            .max()
            .unwrap_or(0);
        (2..=max_per_set).for_each(|_| stats.mul_scalar()); // powers of x1
        (2..=num_point_sets + 1).for_each(|_| stats.mul_scalar()); // powers of x4
    }

    if PCS::pcs_type() == PCSType::GWC19 {
        let sets = group_queries_by_point(circuit.queries.all_ordered());
        let (left, right) = construct_msm(sets);
        let opt_left = left.flatten_msm().optimize_msm();
        let opt_right = right.flatten_msm().optimize_msm();

        stats.msm_operation(&opt_left);
        stats.msm_operation(&opt_right);

        let max_v = opt_left
            .find_max_power('v')
            .max(opt_right.find_max_power('v'));
        (2..=max_v).for_each(|_| stats.mul_scalar());

        let max_u = opt_left
            .find_max_power('u')
            .max(opt_right.find_max_power('u'));
        (2..=max_u).for_each(|_| stats.mul_scalar());
    }

    stats
}
