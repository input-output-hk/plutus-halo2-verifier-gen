//! InstantiationSpecificData struture and associated functions.
//! This structure contains the high level data that is specific to the
//! instantiation of a circuit.

use midnight_curves::{Bls12, BlsScalar as Scalar, G1Affine, G1Projective, G2Affine};

use group::Curve;

use midnight_proofs::plonk::VerifyingKey;
use midnight_proofs::poly::commitment::PolynomialCommitmentScheme;
use midnight_proofs::poly::kzg::params::ParamsKZG;

use ff::Field;
#[cfg(feature = "plutus_debug")]
use log::info;

/// Type listing all instantiation specific data
#[derive(Clone, Debug, Default)]
pub(crate) struct InstantiationSpecificData {
    pub(crate) fixed_commitments: Vec<G1Affine>,
    pub(crate) permutation_commitments: Vec<G1Affine>,
    pub(crate) omega: Scalar,
    pub(crate) inverted_omega: Scalar,
    pub(crate) barycentric_weight: Scalar,
    pub(crate) s_g2: G2Affine,
    pub(crate) omega_rotation_count_for_instances: usize,
    pub(crate) n_coefficient: u64,
    pub(crate) blinding_factors: usize,
    pub(crate) transcript_representation: Scalar,
    pub(crate) public_inputs_count: usize,
}

impl InstantiationSpecificData {
    /// Function to extract the instantiation specific data from the vk, public
    /// inputs and params.
    pub(crate) fn extract<PCS>(
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
