use super::super::{CircuitRepresentation, ProofExtractionSteps};

use midnight_curves::{BlsScalar as Scalar, G1Affine, G1Projective};
use midnight_proofs::plonk::VerifyingKey;
use midnight_proofs::poly::commitment::PolynomialCommitmentScheme;

use ff::Field;
use group::prime::PrimeCurveAffine;

#[cfg(feature = "plutus_debug")]
use log::info;

impl CircuitRepresentation {
    pub fn extract_proof_steps<S>(&mut self, vk: &VerifyingKey<Scalar, S>) -> ()
    where
        S: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
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

        #[cfg(feature = "plutus_debug")]
        info!(
            "proofs: vk phases{} ?= all phases {}",
            Vec::from_iter(vk.cs().phases()).len(),
            all_phases.len()
        );

        for current_phase in all_phases {
            for (phase, _commitment) in vk
                .cs()
                .advice_column_phase()
                .iter()
                .zip(advice_commitments.iter_mut())
            {
                if current_phase == *phase {
                    self.extract_step(ProofExtractionSteps::AdviceCommitments);
                }
            }
            for (phase, _challenge) in vk.cs().challenge_phase().iter().zip(challenges.iter_mut()) {
                if current_phase == *phase {
                    self.extract_step(ProofExtractionSteps::SqueezeChallenge);
                }
            }
        }

        self.extract_step(ProofExtractionSteps::Theta);

        let nb_lookups = vk.cs().lookups().len();
        (0..nb_lookups).for_each(|_argument| {
            self.extract_step(ProofExtractionSteps::LookupPermuted);
        });

        self.extract_step(ProofExtractionSteps::Beta);

        self.extract_step(ProofExtractionSteps::Gamma);

        let nb_permutation_commitments = vk.cs().permutation().columns.chunks(chunk_len).len();

        (0..nb_permutation_commitments).for_each(|_| {
            self.extract_step(ProofExtractionSteps::PermutationsCommitted);
        });

        (0..nb_lookups).for_each(|_| self.extract_step(ProofExtractionSteps::LookupCommitment));

        self.extract_step(ProofExtractionSteps::Trash);

        self.extract_step(ProofExtractionSteps::VanishingRand);

        self.extract_step(ProofExtractionSteps::YCoordinate);

        #[cfg(feature = "plutus_debug")]
        info!("Following Midnight-zk's verify_algebraic_constraints function");

        (0..vk.get_domain().get_quotient_poly_degree()).for_each(|_| {
            self.extract_step(ProofExtractionSteps::VanishingSplit);
        });

        self.extract_step(ProofExtractionSteps::XCoordinate);

        (0..vk.cs().advice_queries().len()).for_each(|_| {
            self.extract_step(ProofExtractionSteps::AdviceEval);
        });

        (0..vk.cs().fixed_queries().len()).for_each(|_| {
            self.extract_step(ProofExtractionSteps::FixedEval);
        });

        self.extract_step(ProofExtractionSteps::RandomEval);

        // for each commitment do a PermutationCommon
        #[cfg(feature = "plutus_debug")]
        info!("nb PermCom: {}", vk.permutation().commitments().len());

        vk.permutation()
            .commitments()
            .iter()
            .enumerate()
            .for_each(|_| {
                self.extract_step(ProofExtractionSteps::PermutationCommon);
            });

        let letters = 'a'..='z';
        let last_index = nb_permutation_commitments - 1;
        (0..nb_permutation_commitments)
            .zip(letters)
            .enumerate()
            .for_each(|(index, (_, letter))| {
                self.extract_permutation_eval(letter);
                self.extract_permutation_eval(letter);

                if index != last_index {
                    self.extract_permutation_eval(letter);
                }
            });

        (0..nb_lookups).for_each(|_| self.extract_step(ProofExtractionSteps::LookupEval));
    }
}
