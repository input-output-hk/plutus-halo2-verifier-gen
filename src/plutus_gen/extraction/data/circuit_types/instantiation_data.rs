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
pub(crate) struct RecursionVK {
    pub(crate) name: String,
    pub(crate) fixed_commitments: Vec<G1Affine>,
    pub(crate) permutation_commitments: Vec<G1Affine>,
    pub(crate) transcript_representation: Scalar,
}

/// Type listing all instantiation specific data
#[derive(Clone, Debug, Default)]
pub(crate) struct InstantiationSpecificData {
    pub(crate) fixed_commitments: Vec<G1Affine>,
    pub(crate) permutation_commitments: Vec<G1Affine>,
    pub(crate) omega: Scalar,
    pub(crate) inverted_omega: Scalar,
    pub(crate) barycentric_weight: Scalar,
    pub(crate) s_g2: G2Affine,
    pub(crate) omega_rotation_count_for_instance: usize,
    pub(crate) n_coefficient: u64,
    pub(crate) blinding_factors: usize,
    pub(crate) transcript_representation: Scalar,
    pub(crate) public_inputs_count: usize,
    pub(crate) committed_instances_supported: bool,
    pub(crate) committed_instances_count: usize,
    pub(crate) recursion_vks: Option<Vec<RecursionVK>>,
}

/// Function returning the minimal and maximal rotations.
fn rotations<PCS>(vk: &VerifyingKey<Scalar, PCS>) -> (i32, i32)
where
    PCS: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
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

impl InstantiationSpecificData {
    /// Function to extract the instantiation specific data from the vk, public
    /// inputs and params.
    pub(crate) fn extract<PCS>(
        &mut self,
        params: &ParamsKZG<Bls12>,
        vk: &VerifyingKey<Scalar, PCS>,
        recursion_vks: Option<Vec<(String, VerifyingKey<Scalar, PCS>)>>,
        instances: &[Scalar],
        committed_instances: Option<G1Projective>,
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

        let (min_rotation, max_rotation) = rotations(vk);
        let max_instance_len = instances.len() as i32;
        let rotations = -max_rotation..max_instance_len + min_rotation.abs();
        self.omega_rotation_count_for_instance = rotations.len();
        // self.mega_rotation_count_for_vanishing - not needed

        self.n_coefficient = vk.n();

        self.blinding_factors = vk.cs().blinding_factors();

        self.transcript_representation = vk.transcript_repr();

        // Extracting number of committed instances
        if committed_instances.is_some() {
            self.committed_instances_supported = true;
            self.committed_instances_count = 1;
        }

        // Extracting number of public_inputs
        self.public_inputs_count = instances.len();

        self.recursion_vks = recursion_vks.map(|recursion_vks| {
            recursion_vks
                .into_iter()
                .map(|(name, vk)| RecursionVK {
                    name,
                    fixed_commitments: vk
                        .fixed_commitments()
                        .iter()
                        .map(|p| p.to_affine())
                        .collect(),
                    permutation_commitments: vk
                        .permutation()
                        .commitments()
                        .iter()
                        .map(|p| p.to_affine())
                        .collect(),
                    transcript_representation: vk.transcript_repr(),
                })
                .collect()
        });
    }
}
