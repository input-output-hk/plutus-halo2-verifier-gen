//! Circuit query structure and associated functions.

use super::super::{Commitments, Evaluations, Query, RotationDescription};

/// CircuitQueries structure
/// This structure contains all circuit's queries.
#[derive(Clone, Debug, Default)]
pub(crate) struct CircuitQueries {
    pub(crate) instance: Vec<Query>,
    pub(crate) advice: Vec<Query>,
    pub(crate) fixed: Vec<Query>,
    pub(crate) permutation: Vec<Query>,
    pub(crate) common: Vec<Query>,
    pub(crate) vanishing: Vec<Query>,
    pub(crate) lookup: Vec<Query>,
    pub(crate) trashcan: Vec<Query>,
}

impl CircuitQueries {
    // Order of queries from halo2:
    // 1. INSTANCE
    // 2. ADVICE
    // 3. PERMUTATION
    // 4. LOOKUP
    // 5. TRASHCAN
    // 6. FIXED
    // 7. COMMON
    // 8. VANISHING
    /// Returns all queries ordered by type.
    pub(crate) fn all_ordered(&self) -> [Vec<Query>; 8] {
        [
            self.advice.clone(),
            self.instance.clone(),
            self.permutation.clone(),
            self.lookup.clone(),
            self.trashcan.clone(),
            self.fixed.clone(),
            self.common.clone(),
            self.vanishing.clone(),
        ]
    }

    /// Extract an advice query to the CircuitQueries structure.
    pub(crate) fn instance(
        &mut self,
        commitment_index: usize,
        evaluation_index: usize,
        point: i32,
    ) {
        let query = Query::new(
            Commitments::Instance(commitment_index), //format!("ci{:?}", column.index() + 1),
            Evaluations::Instance(evaluation_index), //format!("instanceEval{:?}", query_index + 1),
            RotationDescription::from_i32(point),
        );
        self.instance.push(query);
    }

    /// Extract an advice query to the CircuitQueries structure.
    pub(crate) fn advice(&mut self, commitment_index: usize, evaluation_index: usize, point: i32) {
        let query = Query::new(
            Commitments::Advice(commitment_index), //format!("a{:?}", column.index() + 1),
            Evaluations::Advice(evaluation_index), //format!("adviceEval{:?}", query_index + 1),
            RotationDescription::from_i32(point),
        );
        self.advice.push(query);
    }

    /// Extract a fixed query to the CircuitQueries structure.
    pub(crate) fn fixed(&mut self, commitment_index: usize, evaluation_index: usize, point: i32) {
        let query = Query::new(
            Commitments::Fixed(commitment_index), //format!("f{:?}_commitment", column.index() + 1),
            Evaluations::Fixed(evaluation_index), //format!("fixedEval{:?}", query_index + 1),
            RotationDescription::from_i32(point),
        );
        self.fixed.push(query);
    }

    /// Extract a permutation query to the CircuitQueries structure.
    pub(crate) fn permutation(
        &mut self,
        index: char,
        evaluation_subindex: usize,
        point: RotationDescription,
    ) {
        let query = Query::new(
            Commitments::Permutation(index), //format!("permutations_committed_{}", set),
            Evaluations::Permutation(index, evaluation_subindex), //format!("permutations_evaluated_{}_2", set),
            point,
        );
        self.permutation.push(query);
    }

    /// Extract a common permutation query to the CircuitQueries structure.
    pub(crate) fn common(&mut self, index: usize) {
        let query = Query::new(
            Commitments::PermutationsCommon(index), //format!("p{:?}_commitment", idx + 1),
            Evaluations::PermutationsCommon(index), //format!("permutationCommon{:?}", idx + 1),
            RotationDescription::Current,
        );
        self.common.push(query);
    }

    /// Extract a vanishing query to the CircuitQueries structure.
    pub(crate) fn vanishing_queries(&mut self) {
        let query = Query::new(
            Commitments::VanishingG, //"vanishing_g".to_string(),
            Evaluations::VanishingS, //"vanishing_s".to_string()
            RotationDescription::Current,
        );
        self.vanishing.push(query);

        let query = Query::new(
            Commitments::VanishingRand, //"vanishingRand".to_string(),
            Evaluations::RandomEval,    //"randomEval".to_string(),
            RotationDescription::Current,
        );
        self.vanishing.push(query);
    }

    /// Extract a lookup query to the CircuitQueries structure.
    pub(crate) fn lookup(
        &mut self,
        commitment: Commitments,
        evaluation: Evaluations,
        point: RotationDescription,
    ) {
        let query = Query::new(commitment, evaluation, point);
        self.lookup.push(query);
    }

    /// Extract a trashcan query to the CircuitQueries structure.
    pub(crate) fn trashcan(&mut self, index: usize) {
        let query = Query::new(
            Commitments::Trashcan(index),
            Evaluations::Trashcan(index),
            RotationDescription::Current,
        );
        self.trashcan.push(query);
    }
}
