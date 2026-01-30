//! Expression types for scalar and group elements, used as a simple DSL for
//! the verifier side equations that are not part of the prover's.
//! The related functions can be found in the folder expression_steps

use serde::{Deserialize, Serialize};

/// Operations on Scalars
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum ScalarExpression<F> {
    Constant(F),
    Variable(String),
    Advice(usize),
    Fixed(usize),
    Instance(usize),
    PermutationCommon(usize),
    Negated(Box<ScalarExpression<F>>),
    Sum(Box<ScalarExpression<F>>, Box<ScalarExpression<F>>),
    Product(Box<ScalarExpression<F>>, Box<ScalarExpression<F>>),
    PowMod(Box<ScalarExpression<F>>, usize),
}

/// Operations on G1 elements
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ExpressionG1<F> {
    Zero,
    Sum(Box<ExpressionG1<F>>, Box<ExpressionG1<F>>),
    Scale(Box<ExpressionG1<F>>, ScalarExpression<F>),
    VanishingSplit(usize),
    Variable(String),
}
