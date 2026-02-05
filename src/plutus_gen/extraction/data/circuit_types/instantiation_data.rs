//! InstantiationSpecificData struture and associated functions.
//! This structure contains the high level data that is specific to the
//! instantiation of a circuit.

use blstrs::{Bls12, G1Affine, G1Projective, G2Affine, Scalar};

use halo2_proofs::halo2curves::group::Curve;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::PolynomialCommitmentScheme;
use halo2_proofs::poly::kzg::params::ParamsKZG;

use ff::Field;
#[cfg(feature = "plutus_debug")]
use log::info;

/// Type listing all instantiation specific data
#[derive(Clone, Debug, Default)]
pub struct InstantiationSpecificData {
    pub fixed_commitments: Vec<G1Affine>,
    pub permutation_commitments: Vec<G1Affine>,
    pub omega: Scalar,
    pub inverted_omega: Scalar,
    pub barycentric_weight: Scalar,
    pub s_g2: G2Affine,
    pub omega_rotation_count_for_instances: usize,
    pub n_coefficient: u64,
    pub blinding_factors: usize,
    pub transcript_representation: Scalar,
    pub public_inputs_count: usize,
}

impl InstantiationSpecificData {
    /// Function to extract the instantiation specific data from the vk, public
    /// inputs and params.
    pub fn extract<PCS>(
        &mut self,
        params: &ParamsKZG<Bls12>,
        vk: &VerifyingKey<Scalar, PCS>,
        instances: &[&[&[Scalar]]],
        rotations: usize,
    ) where
        PCS: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
    {
        // Importing data from vk (not vk.cs() and params)
        self.fixed_commitments = vk
            .fixed_commitments()
            .iter()
            .map(|p| p.to_affine())
            .collect();
        self.permutation_commitments = vk
            .permutation()
            .commitments()
            .iter()
            .map(|p| p.to_affine())
            .collect();

        self.omega = vk.get_domain().get_omega();
        self.inverted_omega = vk.get_domain().get_omega_inv();
        self.barycentric_weight = Scalar::from(vk.n())
            .invert()
            .expect("there should be an inverse");

        self.s_g2 = params.s_g2().to_affine();

        self.omega_rotation_count_for_instances = rotations;
        // self.mega_rotation_count_for_vanishing - not needed

        self.n_coefficient = vk.n();

        self.blinding_factors = vk.cs().blinding_factors();

        self.transcript_representation = vk.transcript_repr();

        self.public_inputs_count = instances[0][0].len();
    }
}
