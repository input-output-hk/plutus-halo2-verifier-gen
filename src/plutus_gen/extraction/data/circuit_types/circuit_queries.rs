//! Query type

use super::super::{Commitments, Evaluations, Query, RotationDescription};

/// CircuitQueries type
/// This type contains all circuit's queries, that is the expressions' values
/// extracted from the proof.
#[derive(Clone, Debug, Default)]
pub struct CircuitQueries {
    pub advice: Vec<Query>,
    // pub instance: Vec<Query>,
    pub fixed: Vec<Query>,
    pub permutation: Vec<Query>,
    pub common: Vec<Query>,
    pub vanishing: Vec<Query>,
    pub lookup: Vec<Query>,
}

impl CircuitQueries {
    // Order of queries from halo2:
    // 1.ADVICE
    // 2. PERMUTATION
    // 3. LOOKUP
    // 4. FIXED
    // 5. COMMON
    // 6. VANISHING
    pub fn all_ordered(&self) -> [Vec<Query>; 6] {
        [
            self.advice.clone(),
            self.permutation.clone(),
            self.lookup.clone(),
            self.fixed.clone(),
            self.common.clone(),
            self.vanishing.clone(),
        ]
    }
}

impl CircuitQueries {
    pub fn advice(&mut self, commitment_index: usize, evaluation_index: usize, point: i32) -> () {
        let query = Query::new(
            Commitments::Advice(commitment_index), //format!("a{:?}", column.index() + 1),
            Evaluations::Advice(evaluation_index), //format!("adviceEval{:?}", query_index + 1),
            RotationDescription::from_i32(point),
        );
        self.advice.push(query);
    }

    pub fn fixed(&mut self, commitment_index: usize, evaluation_index: usize, point: i32) -> () {
        let query = Query::new(
            Commitments::Fixed(commitment_index), //format!("f{:?}_commitment", column.index() + 1),
            Evaluations::Fixed(evaluation_index), //format!("fixedEval{:?}", query_index + 1),
            RotationDescription::from_i32(point),
        );
        self.fixed.push(query);
    }

    pub fn permutation(
        &mut self,
        index: char,
        evaluation_subindex: usize,
        point: RotationDescription,
    ) -> () {
        let query = Query::new(
            Commitments::Permutation(index), //format!("permutations_committed_{}", set),
            Evaluations::Permutation(index, evaluation_subindex), //format!("permutations_evaluated_{}_2", set),
            point,
        );
        self.permutation.push(query);
    }

    pub fn common(&mut self, index: usize) -> () {
        let query = Query::new(
            Commitments::PermutationsCommon(index), //format!("p{:?}_commitment", idx + 1),
            Evaluations::PermutationsCommon(index), //format!("permutationCommon{:?}", idx + 1),
            RotationDescription::Current,
        );
        self.common.push(query);
    }

    pub fn vanishing_queries(&mut self) -> () {
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

    pub fn lookup(
        &mut self,
        commitment: Commitments,
        evaluation: Evaluations,
        point: RotationDescription,
    ) -> () {
        let query = Query::new(commitment, evaluation, point);
        self.lookup.push(query);
    }
}
