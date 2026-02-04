use crate::plutus_gen::extraction::data::CircuitRepresentation;
use itertools::Itertools;

use super::{ExtractPCS, PCSType};

use blstrs::Bls12;
use halo2_proofs::poly::gwc_kzg::GwcKZGCommitmentScheme;

#[cfg(feature = "plutus_debug")]
use log::info;

type GWC19Scheme = GwcKZGCommitmentScheme<Bls12>;

#[derive(Default)]
pub struct GWC19Data {
    w_values_count: usize,
}

#[derive(PartialEq, Clone, Debug)]
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

    fn pcs_data(circuit_repr: &CircuitRepresentation<Self>) -> usize {
        circuit_repr.pcs_instantiation_data.w_values_count
    }
    fn pcs_data_aiken(_circuit_repr: &CircuitRepresentation<Self>) -> String {
        // Not used in Aiken
        "".to_string()
    }

    fn pcs_data_plinth(circuit_repr: &CircuitRepresentation<Self>) -> String {
        (1..=circuit_repr.pcs_instantiation_data.w_values_count)
            .map(|n| format!("              'w{}", n))
            .join(" ,\n")
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

    fn step_to_aiken(step: Self::PCSExtractionSteps, number: usize) -> String {
        match step {
            GWC19Steps::U => {
                "    let (u, transcript) = squeeze_challenge(transcript)\n".to_string()
            }
            GWC19Steps::V => {
                "    let (v, transcript) = squeeze_challenge(transcript)\n".to_string()
            }
            GWC19Steps::Witnesses => format!(
                "    let (w{}, transcript) =  read_point(transcript)\n",
                number
            ),
        }
    }

    fn step_to_plinth(step: Self::PCSExtractionSteps, number: usize) -> String {
        match step {
            GWC19Steps::U => "  !u <- M.squeezeChallenge\n".to_string(),
            GWC19Steps::V => "  !v <- M.squeezeChallenge\n".to_string(),
            GWC19Steps::Witnesses => format!("  !w{} <- M.readPoint\n", number),
        }
    }
}
