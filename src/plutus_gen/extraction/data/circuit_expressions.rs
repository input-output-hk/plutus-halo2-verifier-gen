use super::{CircuitRepresentation, ExpressionG1, ScalarExpression};

use midnight_curves::BlsScalar as Scalar;
use midnight_proofs::plonk::Expression;

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
    pub compiled_trashcans: Vec<(String, Expression<Scalar>, Vec<Expression<Scalar>>)>,
}

impl CircuitRepresentation {
    pub fn gate_expression(&mut self, expression: Expression<Scalar>) -> () {
        self.expressions.compiled_gate_equations.push(expression);
    }

    pub fn lookup_expression(
        &mut self,
        inputs: Vec<Expression<Scalar>>,
        tables: Vec<Expression<Scalar>>,
    ) -> () {
        self.expressions.compiled_lookups_equations.0.push(inputs);
        self.expressions.compiled_lookups_equations.1.push(tables);
    }

    pub fn permutation_eval_expression(&mut self, expression: ScalarExpression<Scalar>) -> () {
        self.expressions
            .permutations_evaluated_terms
            .push(expression);
    }

    pub fn permutation_left_expression(
        &mut self,
        index: char,
        expression: ScalarExpression<Scalar>,
    ) -> () {
        self.expressions
            .permutation_terms_left
            .push((index, expression));
    }

    pub fn permutation_right_expression(
        &mut self,
        index: char,
        expression: ScalarExpression<Scalar>,
    ) -> () {
        self.expressions
            .permutation_terms_right
            .push((index, expression));
    }

    pub fn vanishing_expression(&mut self, name: String, expression: ExpressionG1<Scalar>) -> () {
        self.expressions.h_commitments.push((name, expression));
    }

    pub fn trashcan_expression(
        &mut self,
        name: String,
        selector: Expression<Scalar>,
        expressions: Vec<Expression<Scalar>>,
    ) -> () {
        self.expressions
            .compiled_trashcans
            .push((name, selector, expressions));
    }
}
