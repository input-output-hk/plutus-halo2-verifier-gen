//! InstantiationData type
//! This type

use super::CircuitRepresentation;

use midnight_curves::{Bls12, BlsScalar as Scalar, G1Affine, G1Projective, G2Affine};
use midnight_proofs::plonk::VerifyingKey;
use midnight_proofs::poly::commitment::PolynomialCommitmentScheme;
use midnight_proofs::poly::kzg::params::ParamsKZG;

use ff::Field;
use group::Curve;
#[cfg(feature = "plutus_debug")]
use log::info;

/// Type listing all instantiation specific data
#[derive(Clone, Debug, Default)]
pub struct InstantiationSpecificData {
    pub fixed_commitments: Vec<G1Affine>,
    pub permutation_commitments: Vec<G1Affine>,

    // values as hex
    // pub scalar_delta: Scalar,
    // pub scalar_zero: Scalar,
    // pub scalar_one: Scalar,
    pub omega: Scalar,
    pub inverted_omega: Scalar,
    pub barycentric_weight: Scalar,

    pub s_g2: G2Affine,

    pub omega_rotation_count_for_instances: usize,
    // pub omega_rotation_count_for_vanishing: usize,
    pub n_coefficient: u64,

    pub blinding_factors: usize,

    pub transcript_representation: Scalar,

    pub public_inputs_count: usize,

    // pub w_values_count: usize,
    pub q_evaluations_count: usize,
}

impl CircuitRepresentation {
    pub fn extract_instantiation_data<S>(
        &mut self,
        params: &ParamsKZG<Bls12>,
        vk: &VerifyingKey<Scalar, S>,
        instances: &[&[&[Scalar]]],
        rotations: usize,
    ) -> ()
    where
        S: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
    {
        // Importing data from vk (not vk.cs() and params)
        self.instantiation_data.fixed_commitments = vk
            .fixed_commitments()
            .iter()
            .map(|p| p.to_affine())
            .collect();
        self.instantiation_data.permutation_commitments = vk
            .permutation()
            .commitments()
            .iter()
            .map(|p| p.to_affine())
            .collect();

        // self.instantiation_data.scalar_delta - not vk specific
        // self.instantiation_data.scalar_zero - not vk specific
        // self.instantiation_data.scalar_one - not vk specific

        self.instantiation_data.omega = vk.get_domain().get_omega();
        self.instantiation_data.inverted_omega = vk.get_domain().get_omega_inv();
        self.instantiation_data.barycentric_weight = Scalar::from(vk.n())
            .invert()
            .expect("there should be an inverse");

        self.instantiation_data.s_g2 = params.s_g2().to_affine();

        self.instantiation_data.omega_rotation_count_for_instances = rotations;
        // self.instantiation_data.mega_rotation_count_for_vanishing - not needed

        self.instantiation_data.n_coefficient = vk.n();

        self.instantiation_data.blinding_factors = vk.cs().blinding_factors();

        self.instantiation_data.transcript_representation = vk.transcript_repr();

        self.instantiation_data.public_inputs_count = {
            if instances[0].len() == 1 {
                instances[0][0].len()
            } else {
                // we have committed instances
                instances[0][1].len()
            }
        };

        // self.instantiation_data.w_values_count - not needed

        // self.instantiation_data.q_evaluations_count - Computed in kzg
    }
}
