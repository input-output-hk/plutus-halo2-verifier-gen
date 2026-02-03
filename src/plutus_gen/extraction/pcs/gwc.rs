use crate::plutus_gen::extraction::data::CircuitRepresentation;
use itertools::Itertools;

use super::{ExtractPCS, IntermediateSets, PCSType};

use blstrs::Bls12;
use halo2_proofs::poly::gwc_kzg::GwcKZGCommitmentScheme;

#[cfg(feature = "plutus_debug")]
use log::info;

type GWC19Scheme = GwcKZGCommitmentScheme<Bls12>;

#[derive(Default)]
pub struct GWC19Data {
    w_values_count: usize,
}

pub enum GWC19Steps {
    U,
    V,
    Witnesses,
}

impl ExtractPCS for GWC19Scheme {
    type PCSExtractionSteps = GWC19Steps;
    type PCSData = GWC19Data;
    fn pcs_type() -> PCSType {
        PCSType::GWC19
    }
    fn precompute_intermediate_sets(
        _circuit_repr: &CircuitRepresentation<Self>,
    ) -> IntermediateSets {
        (Vec::new(), Vec::new())
    }

    fn extract_pcs_steps(circuit_repr: &mut CircuitRepresentation<Self>) {
        circuit_repr.pcs_extraction_steps.push(GWC19Steps::V);

        // TODO double check if number of final witnesses is equal to number of different X rotations
        let number_of_witnesses = circuit_repr
            .queries
            .all_ordered()
            .iter()
            .flatten()
            .map(|q| q.point.clone())
            .unique()
            .count();

        circuit_repr.pcs_instantiation_data.w_values_count = number_of_witnesses;
        for _ in 0..number_of_witnesses {
            circuit_repr
                .pcs_extraction_steps
                .push(GWC19Steps::Witnesses);
        }

        circuit_repr.pcs_extraction_steps.push(GWC19Steps::U);
    }
}
