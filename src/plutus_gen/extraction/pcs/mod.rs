use super::data::{CircuitRepresentation, CommitmentData, Commitments, Query, RotationDescription};

#[cfg(feature = "plutus_debug")]
use log::info;

use itertools::Itertools;
use std::collections::HashMap;

pub(crate) mod gwc;
pub(crate) mod kzg;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PCSType {
    GWC19,
    Halo2MultiOpen,
}

pub type IntermediateSets = (Vec<Vec<RotationDescription>>, Vec<CommitmentData>);

pub trait ExtractPCS {
    type PCSExtractionSteps: PartialEq + Clone;

    type PCSData: Default;

    fn precompute_intermediate_sets(
        circuit_repr: &CircuitRepresentation<Self>,
    ) -> IntermediateSets {
        let queries = circuit_repr.queries.all_ordered();

        let ordered_unique_commitments = queries.iter().flatten().map(|q| &q.commitment);
        let ordered_unique_commitments: Vec<Commitments> =
            ordered_unique_commitments.cloned().unique().collect();

        let commitment_map: HashMap<Commitments, Vec<&Query>> = queries
            .iter()
            .flatten()
            .into_group_map_by(|e| e.commitment.clone());

        let point_sets_map: HashMap<Commitments, Vec<RotationDescription>> = commitment_map
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.iter()
                        .map(|e| &e.point)
                        .cloned()
                        .unique()
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        let mut grouped_points: Vec<Vec<RotationDescription>> = vec![];

        for commitment in ordered_unique_commitments.iter() {
            grouped_points.push(
                point_sets_map
                    .get(commitment)
                    .unwrap_or_else(|| {
                        panic!("point set for commitment {:?} not found", commitment)
                    })
                    .clone(),
            );
        }

        let unique_grouped_points: Vec<Vec<_>> = grouped_points.iter().cloned().unique().collect();

        let point_sets_indexes: HashMap<_, _> = unique_grouped_points
            .iter()
            .enumerate()
            .map(|(a, b)| (b.clone(), a))
            .collect();

        let mut commitment_data: Vec<CommitmentData> = vec![];

        for commitment in ordered_unique_commitments.iter() {
            let query = commitment_map
                .get(commitment)
                .unwrap_or_else(|| panic!("queries for commitment {:?} not found", commitment));
            let points: Vec<RotationDescription> = query.iter().map(|q| q.point.clone()).collect();

            let point_set_idx = point_sets_indexes
                .get(&points)
                .unwrap_or_else(|| panic!("point set for commitment {:?} not found", commitment));

            commitment_data.push(CommitmentData {
                commitment: (*commitment).clone(),
                point_set_index: *point_set_idx,
                evaluations: query.iter().map(|q| q.evaluation.clone()).collect(),
                points,
            });
        }
        (unique_grouped_points, commitment_data)
    }

    fn extract_pcs_steps(circuit_repr: &mut CircuitRepresentation<Self>);
    fn step_to_aiken(step: Self::PCSExtractionSteps, number: usize) -> String;
    fn step_to_plinth(step: Self::PCSExtractionSteps, number: usize) -> String;

    fn pcs_data(circuit_repr: &CircuitRepresentation<Self>) -> usize;
    fn pcs_data_aiken(circuit_repr: &CircuitRepresentation<Self>) -> String;
    fn pcs_data_plinth(circuit_repr: &CircuitRepresentation<Self>) -> String;

    fn pcs_type() -> PCSType;
}
