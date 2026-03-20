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
    pub(crate) committed_instances_supported: bool,
    pub(crate) committed_instances_count: usize,
}

/// Function returning the maximal length of the instances.
fn instance_max_length(instances: &[&[&[Scalar]]]) -> usize {
    instances
        .iter()
        .flat_map(|instance| instance.iter().map(|instance| instance.len()))
        .max_by(Ord::cmp)
        .unwrap_or_default()
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
        instances: &[&[&[Scalar]]],
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
        let max_instance_len = instance_max_length(instances) as i32;
        let rotations = -max_rotation..max_instance_len + min_rotation.abs();
        self.omega_rotation_count_for_instances = rotations.len();
        // self.mega_rotation_count_for_vanishing - not needed

        self.n_coefficient = vk.n();

        self.blinding_factors = vk.cs().blinding_factors();

        self.transcript_representation = vk.transcript_repr();

        // The committed instances and public inputs are both stored in the
        // instances. More precisely, we have either:
        // -  instances  = &[&[public_inputs]] or
        // -  instances  = &[&[committed_instances, public_inputs]]
        // depending on whether the commited instances are supported.

        // Extracting number of committed instances
        if instances[0].len() == 2 {
            self.committed_instances_supported = true;
            self.committed_instances_count = 1;
        }

        // Extracting number of public_inputs
        let mut index_public_inputs = 0;
        if self.committed_instances_supported {
            index_public_inputs = 1;
        }
        self.public_inputs_count = instances[0][index_public_inputs].len();
    }
}
