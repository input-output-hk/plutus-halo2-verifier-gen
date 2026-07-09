//! Exact verifier cost computation from a fully extracted `CircuitRepresentation`.
use itertools::Itertools;
use midnight_curves::{BlsScalar as Scalar, G1Projective};
use midnight_proofs::{
    plonk::VerifyingKey, poly::commitment::PolynomialCommitmentScheme, utils::SerdeFormat,
};
use std::collections::HashMap;

use crate::plutus_gen::extraction::data::{CircuitRepresentation, ProofExtractionSteps};
use crate::plutus_gen::extraction::pcs::ExtractPCS;

use super::data::CircuitStatistics;

/// Computes the exact verifier operation counts for a circuit whose representation has
/// already been fully extracted. Use `estimate_verifier_code` when no circuit is available.
///
/// `vk` is the circuit verification key
/// `circuit` is the circuit representation extracted from the vk and circuit constraints.
pub fn compute_verifier_code<PCS>(
    vk: &VerifyingKey<Scalar, PCS>,
    circuit: &CircuitRepresentation<PCS>,
) -> CircuitStatistics
where
    PCS: ExtractPCS + PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
    let nb_public_inputs = circuit.proof_instantiation_data.public_inputs_count;
    let nb_committed_instances = circuit.proof_instantiation_data.committed_instances_count;
    let committed_instances_supported = circuit
        .proof_instantiation_data
        .committed_instances_supported;

    let bf = circuit.proof_instantiation_data.blinding_factors;

    let size_proof = {
        let (pes_commitments, pes_scalars) =
            circuit
                .proof_extraction_steps
                .iter()
                .fold((0, 0), |acc, pes| {
                    let (c, s) = match pes {
                        // CommittedInstanceEval reads a scalar from the proof only when
                        // there are actual committed instances; otherwise it emits a zero constant.
                        ProofExtractionSteps::CommittedInstanceEval => {
                            (0, usize::from(nb_committed_instances > 0))
                        }
                        _ => pes.step_stat(),
                    };
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
        vk.cs().degree(),
        circuit.proof_instantiation_data.public_inputs_count,
        circuit.proof_instantiation_data.committed_instances_count,
    );

    // Converting constants 0, 1 and δ to scalars
    (0..3).for_each(|_| stats.int_to_scalar());

    // Absorb vk,
    stats.common_scalar();

    // Absorb committed instances
    if nb_committed_instances > 0 {
        stats.common_g1();
    }

    // Absorb public-input count, and each PI value
    stats.int_to_scalar();
    stats.common_scalar();
    (0..nb_public_inputs).for_each(|_| stats.common_scalar());

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
            ProofExtractionSteps::VanishingSplit => group.for_each(|_| {stats.read_point(); stats.decompress_point();}),
            ProofExtractionSteps::XCoordinate => {
                stats.squeeze_challenge();
                // Evaluation point setup: scale(x, n-1) then mul(x^(n-1), x) = x^n
                stats.pow_scalar();
                stats.mul_scalar();
            },
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
            ProofExtractionSteps::Trash => stats.squeeze_challenge(),
            ProofExtractionSteps::TrashCommitment => group.for_each(|_| {
                stats.read_point();}),
            ProofExtractionSteps::TrashEval => group.for_each(|_| {
                stats.read_scalar();
            }),
            ProofExtractionSteps::CommittedInstanceEval => group.for_each(|_| {
                match (committed_instances_supported,nb_committed_instances) {
                    (false, _) => panic!("This case should never happen, as we should not have any CommittedInstanceEval"),
                    (true, 0) => stats.int_to_scalar(),
                    (true, _) => stats.read_scalar(),
                }
            }),
            ProofExtractionSteps::InstanceEval => group.for_each(|_| {
                if nb_public_inputs == 0 {
                    stats.int_to_scalar();
                } else {

                    (0..=nb_public_inputs).for_each(|_| stats.rotate_omega());
                    stats.lagrange_polynomial_basis(nb_public_inputs+1);
                    stats.inner_product(nb_public_inputs+1);
                }
            })
        });

    circuit
        .pcs_extraction_steps
        .iter()
        .chunk_by(|e| (*e).clone())
        .into_iter()
        .for_each(|(_section_type, section)| {
            section.for_each(|step| PCS::step_stat_operation(&mut stats, step))
        });

    let expected_transcript_size = 32 // absorbing hash of vk
    + 48 * nb_committed_instances // absorbing committed inputs
    + 32 // absorbing nb of public inputs
    + 32 * nb_public_inputs // absorbing public inputs
    + size_proof; // aborsbing proof
    assert_eq!(stats.transcript_size, expected_transcript_size);

    // Rotate ω once per point set
    let (unique_grouped_points, _commitment_data) = PCS::precompute_intermediate_sets(circuit);
    (0..unique_grouped_points.len()).for_each(|_| stats.rotate_omega());

    // Rotations of the blinding factors for vanishing polynomial
    (0..bf + 2).for_each(|_| stats.rotate_omega());

    // TODO CHECK if we do not double count here
    // Lagrange basis and active-rows scalar for blinding factors
    stats.lagrange_polynomial_basis(2 + bf);

    // sum_of_evaluation_for_blinding_factors: Summing all evaluation_for_blinding_factors, starting with a 0 accumulator
    (0..bf + 1).for_each(|_| stats.add_scalar());

    // active_rows
    stats.add_scalar();
    stats.sub_scalar();

    // Gate equations
    circuit
        .expressions
        .compiled_gate_equations
        .iter()
        .for_each(|gate| {
            stats.expression(gate);
        });

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
        stats.sub_scalar(); // l1: (1 - product_eval)
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

    // Trashcan constraint evaluation (one argument per compiled trashcan):
    //   1. Evaluate each constraint expression and fold with trash_challenge: acc * challenge + eval
    //   2. Evaluate the selector expression
    //   3. Final check: compressed - (1 - q) * trash_eval
    for (_, selector, constraint_exprs) in &circuit.expressions.compiled_trashcans {
        for expr in constraint_exprs {
            stats.expression(expr);
            stats.mul_scalar(); // acc * trash_challenge
            stats.add_scalar(); // + eval
        }
        stats.expression(selector);
        stats.sub_scalar(); // 1 - q
        stats.mul_scalar(); // (1 - q) * trash_eval
        stats.sub_scalar(); // compressed - (1 - q) * trash_eval
    }

    // Expressions combiner
    let total_expressions = circuit.expressions.compiled_gate_equations.len()
        + circuit.expressions.permutations_evaluated_terms.len()
        + sets_lhs.len()
        + circuit.expressions.compiled_lookups_equations.0.len() * 5
        + circuit.expressions.compiled_trashcans.len();
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
    PCS::opening_stat(&mut stats, circuit);

    // If we do recursion
    if circuit.proof_instantiation_data.recursion_vks.is_some() {
        // Compute variable accumulator left point from public inputs
        (0..2).for_each(|_| {
            // For both coordinates of the point, we reconstruct the coordinate from the 2 chunks
            (0..2).for_each(|_| {
                stats.add_scalar();
                stats.mul_scalar();
            });
        });
        stats.g1_from_coords();
        stats.scale();

        // Compute variable accumulator right point from public inputs
        // Compute variable accumulator left point from public inputs
        (0..2).for_each(|_| {
            // For both coordinates of the point, we reconstruct the coordinate from the 2 chunks
            (0..2).for_each(|_| {
                stats.add_scalar();
                stats.mul_scalar();
            });
        });
        stats.g1_from_coords();
        stats.scale();

        // Compute fixed accumulator
        let vk_len = vk.fixed_commitments().len() + vk.permutation().commitments().len();
        // The MSM also comprises the negated generator, and 2 group elements
        // for the public inputs and committed instances.
        stats.msm(vk_len + 3);
        (0..vk_len).for_each(|_| {
            stats.decompress_point();
        });

        // Combine fixed and variable accumulators (only on the right)
        stats.add_point();

        // Compute batching coefficient to batch accumulator check with proof check
        (0..4).for_each(|_| stats.compress_point());
        stats.hash_bytes(4 * 48);
        // bytes to int
        stats.int_to_scalar();

        // Batch left and right accumulators with proof before Miller Loop
        (0..2).for_each(|_| {
            stats.scale();
            stats.add_point();
        });
    }

    stats
}
