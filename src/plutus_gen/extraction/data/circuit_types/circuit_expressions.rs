use super::super::{ExpressionG1, ScalarExpression};

use blstrs::Scalar;
use halo2_proofs::plonk::Expression;
/// CircuitExpressions type
/// This type contains all expressions a circuit must satisfy.
/// These are extracted from the verifying key.
#[derive(Clone, Debug, Default)]
pub struct CircuitExpressions {
    pub compiled_gate_equations: Vec<Expression<Scalar>>,
    pub compiled_lookups_equations: (Vec<Vec<Expression<Scalar>>>, Vec<Vec<Expression<Scalar>>>),
    pub permutations_evaluated_terms: Vec<ScalarExpression<Scalar>>,
    pub permutation_terms_left: Vec<(char, ScalarExpression<Scalar>)>,
    pub permutation_terms_right: Vec<(char, ScalarExpression<Scalar>)>,
    pub h_commitments: Vec<(String, ExpressionG1<Scalar>)>,
}

impl CircuitExpressions {
    pub fn gate(&mut self, expression: Expression<Scalar>) -> () {
        self.compiled_gate_equations.push(expression);
    }

    pub fn lookup(
        &mut self,
        inputs: Vec<Expression<Scalar>>,
        tables: Vec<Expression<Scalar>>,
    ) -> () {
        self.compiled_lookups_equations.0.push(inputs);
        self.compiled_lookups_equations.1.push(tables);
    }

    pub fn permutation_eval(&mut self, expression: ScalarExpression<Scalar>) -> () {
        self.permutations_evaluated_terms.push(expression);
    }

    pub fn permutation_left(&mut self, index: char, expression: ScalarExpression<Scalar>) -> () {
        self.permutation_terms_left.push((index, expression));
    }

    pub fn permutation_right(&mut self, index: char, expression: ScalarExpression<Scalar>) -> () {
        self.permutation_terms_right.push((index, expression));
    }

    pub fn vanishing(&mut self, name: String, expression: ExpressionG1<Scalar>) -> () {
        self.h_commitments.push((name, expression));
    }
}
