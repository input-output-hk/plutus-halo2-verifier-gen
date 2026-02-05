//! Code for extracting common expressions.

use super::super::{CircuitRepresentation, ProofExtractionSteps};
use crate::plutus_gen::extraction::pcs::ExtractPCS;

use blstrs::{G1Affine, G1Projective, Scalar};
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::PolynomialCommitmentScheme;

use ff::Field;
use halo2_proofs::halo2curves::group::prime::PrimeCurveAffine;

#[cfg(feature = "plutus_debug")]
use log::info;

pub fn extract_proof_steps<PCS>(
    circuit_repr: &mut CircuitRepresentation<PCS>,
    vk: &VerifyingKey<Scalar, PCS>,
) where
    PCS: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective> + ExtractPCS,
{
    let chunk_len = vk.cs().degree() - 2;

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
                circuit_repr.extract_step(ProofExtractionSteps::AdviceCommitments);
            }
        }
        for (phase, _challenge) in vk.cs().challenge_phase().iter().zip(challenges.iter_mut()) {
            if current_phase == *phase {
                circuit_repr.extract_step(ProofExtractionSteps::SqueezeChallenge);
            }
        }
    }

    circuit_repr.extract_step(ProofExtractionSteps::Theta);

    let nb_lookups = vk.cs().lookups().len();
    (0..nb_lookups).for_each(|_argument| {
        circuit_repr.extract_step(ProofExtractionSteps::LookupPermuted);
    });

    circuit_repr.extract_step(ProofExtractionSteps::Beta);

    circuit_repr.extract_step(ProofExtractionSteps::Gamma);

    let nb_permutation_commitments = vk.cs().permutation().columns.chunks(chunk_len).len();

    (0..nb_permutation_commitments).for_each(|_| {
        circuit_repr.extract_step(ProofExtractionSteps::PermutationsCommitted);
    });

    (0..nb_lookups).for_each(|_| circuit_repr.extract_step(ProofExtractionSteps::LookupCommitment));

    circuit_repr.extract_step(ProofExtractionSteps::VanishingRand);

    circuit_repr.extract_step(ProofExtractionSteps::YCoordinate);

    (0..vk.get_domain().get_quotient_poly_degree()).for_each(|_| {
        circuit_repr.extract_step(ProofExtractionSteps::VanishingSplit);
    });

    circuit_repr.extract_step(ProofExtractionSteps::XCoordinate);

    (0..vk.cs().advice_queries().len()).for_each(|_| {
        circuit_repr.extract_step(ProofExtractionSteps::AdviceEval);
    });

    (0..vk.cs().fixed_queries().len()).for_each(|_| {
        circuit_repr.extract_step(ProofExtractionSteps::FixedEval);
    });

    circuit_repr.extract_step(ProofExtractionSteps::RandomEval);

    (0..vk.permutation().commitments().len()).for_each(|_| {
        circuit_repr.extract_step(ProofExtractionSteps::PermutationCommon);
    });

    let letters = 'a'..='z';
    let last_index = nb_permutation_commitments - 1;
    (0..nb_permutation_commitments)
        .zip(letters)
        .enumerate()
        .for_each(|(index, (_, letter))| {
            circuit_repr.extract_permutation_eval(letter);
            circuit_repr.extract_permutation_eval(letter);

            if index != last_index {
                circuit_repr.extract_permutation_eval(letter);
            }
        });

    (0..nb_lookups).for_each(|_| circuit_repr.extract_step(ProofExtractionSteps::LookupEval));
}
