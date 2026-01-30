//! Query type

use super::*;

/// CircuitQueries type
/// This type contains all circuit's queries, that is the expressions' values
/// extracted from the proof.
#[derive(Clone, Debug, Default)]
pub struct CircuitQueries {
    pub advice: Vec<Query>,
    pub instance: Vec<Query>,
    pub fixed: Vec<Query>,
    pub permutation: Vec<Query>,
    pub common: Vec<Query>,
    pub vanishing: Vec<Query>,
    pub lookup: Vec<Query>,
    pub trashcan: Vec<Query>,
}

/// This type is used to store the relation between commitments and evaluations
/// as well as the associated rotation.
#[derive(Clone, Copy, Debug, Default)]
pub struct Query {
    pub commitment: Commitments,
    pub evaluation: Evaluations,
    pub point: RotationDescription,
}

impl Query {
    pub fn new(
        commitment: Commitments,
        evaluation: Evaluations,
        point: RotationDescription,
    ) -> Query {
        Query {
            commitment,
            evaluation,
            point,
        }
    }
}

impl CircuitRepresentation {
    pub fn advice_query(
        &mut self,
        commitment: Commitments,
        evaluation: Evaluations,
        point: RotationDescription,
    ) -> () {
        let query = Query::new(commitment, evaluation, point);
        self.queries.advice.push(query);
    }

    pub fn instance_query(
        &mut self,
        commitment: Commitments,
        evaluation: Evaluations,
        point: RotationDescription,
    ) -> () {
        let query = Query::new(commitment, evaluation, point);
        self.queries.instance.push(query);
    }

    pub fn fixed_query(
        &mut self,
        commitment: Commitments,
        evaluation: Evaluations,
        point: RotationDescription,
    ) -> () {
        let query = Query::new(commitment, evaluation, point);
        self.queries.fixed.push(query);
    }

    pub fn permutation_query(
        &mut self,
        commitment: Commitments,
        evaluation: Evaluations,
        point: RotationDescription,
    ) -> () {
        let query = Query::new(commitment, evaluation, point);
        self.queries.permutation.push(query);
    }

    pub fn common_query(
        &mut self,
        commitment: Commitments,
        evaluation: Evaluations,
        point: RotationDescription,
    ) -> () {
        let query = Query::new(commitment, evaluation, point);
        self.queries.common.push(query);
    }

    pub fn vanishing_query(
        &mut self,
        commitment: Commitments,
        evaluation: Evaluations,
        point: RotationDescription,
    ) -> () {
        let query = Query::new(commitment, evaluation, point);
        self.queries.vanishing.push(query);
    }

    pub fn lookup_query(
        &mut self,
        commitment: Commitments,
        evaluation: Evaluations,
        point: RotationDescription,
    ) -> () {
        let query = Query::new(commitment, evaluation, point);
        self.queries.lookup.push(query);
    }

    pub fn trashcan_query(
        &mut self,
        commitment: Commitments,
        evaluation: Evaluations,
        point: RotationDescription,
    ) -> () {
        let query = Query::new(commitment, evaluation, point);
        self.queries.trashcan.push(query);
    }
}
