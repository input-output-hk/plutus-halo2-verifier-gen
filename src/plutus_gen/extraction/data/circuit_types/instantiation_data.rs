//! InstantiationData type
//! This type

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
}

impl InstantiationSpecificData {
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

        // self.scalar_delta - not vk specific
        // self.scalar_zero - not vk specific
        // self.scalar_one - not vk specific

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

        self.public_inputs_count = {
            if instances[0].len() == 1 {
                instances[0][0].len()
            } else {
                // we have committed instances
                instances[0][1].len()
            }
        };
    }
}
