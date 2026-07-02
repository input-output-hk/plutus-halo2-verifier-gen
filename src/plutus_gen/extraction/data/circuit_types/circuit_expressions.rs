//! Circuit expressions structure and associated functions.

use super::super::{ExpressionG1, ScalarExpression};

use midnight_curves::BlsScalar as Scalar;
use midnight_proofs::plonk::Expression;

/// Compiled lookup argument equations, as `(inputs, tables)` pairs.
pub(crate) type LookupEquations = (Vec<Vec<Expression<Scalar>>>, Vec<Vec<Expression<Scalar>>>);

/// CircuitExpressions structure
/// This structure contains all expressions a circuit must satisfy.
/// These are extracted from the verifying key.
#[derive(Clone, Debug, Default)]
pub(crate) struct CircuitExpressions {
    pub(crate) compiled_gate_equations: Vec<Expression<Scalar>>,
    pub(crate) compiled_lookups_equations: LookupEquations,
    pub(crate) compiled_trashcans: Vec<(String, Expression<Scalar>, Vec<Expression<Scalar>>)>,
    pub(crate) permutations_evaluated_terms: Vec<ScalarExpression<Scalar>>,
    pub(crate) permutation_terms_left: Vec<(char, ScalarExpression<Scalar>)>,
    pub(crate) permutation_terms_right: Vec<(char, ScalarExpression<Scalar>)>,
    pub(crate) h_commitments: Vec<(String, ExpressionG1<Scalar>)>,
}

impl CircuitExpressions {
    /// Extract a gate expression to the CircuitExpressions structure.
    pub(crate) fn gate(&mut self, expression: Expression<Scalar>) {
        self.compiled_gate_equations.push(expression);
    }

    /// Extract a lookup expression to the CircuitExpressions structure.
    pub(crate) fn lookup(
        &mut self,
        inputs: Vec<Expression<Scalar>>,
        tables: Vec<Expression<Scalar>>,
    ) {
        self.compiled_lookups_equations.0.push(inputs);
        self.compiled_lookups_equations.1.push(tables);
    }

    /// Extract a permutation evaluation expression to the CircuitExpressions
    /// structure.
    pub(crate) fn permutation_eval(&mut self, expression: ScalarExpression<Scalar>) {
        self.permutations_evaluated_terms.push(expression);
    }

    /// Extract a permutation left expression to the CircuitExpressions
    /// structure.
    pub(crate) fn permutation_left(&mut self, index: char, expression: ScalarExpression<Scalar>) {
        self.permutation_terms_left.push((index, expression));
    }

    /// Extract a permutation right expression to the CircuitExpressions
    /// structure.
    pub(crate) fn permutation_right(&mut self, index: char, expression: ScalarExpression<Scalar>) {
        self.permutation_terms_right.push((index, expression));
    }

    /// Extract a vanishing, h_commitment, expression to the CircuitExpressions
    /// structure.
    pub(crate) fn vanishing(&mut self, name: String, expression: ExpressionG1<Scalar>) {
        self.h_commitments.push((name, expression));
    }

    /// Extract a trashcan expression to the CircuitExpressions structure.
    pub(crate) fn trashcan(
        &mut self,
        name: String,
        selector: Expression<Scalar>,
        expression: Vec<Expression<Scalar>>,
    ) {
        self.compiled_trashcans.push((name, selector, expression));
    }
}
