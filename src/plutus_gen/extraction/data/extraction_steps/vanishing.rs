//! Code for extracting vasnishing related expressions.

use super::super::{CircuitRepresentation, ExpressionG1, ScalarExpression, constants::*};
use crate::plutus_gen::extraction::pcs::ExtractPCS;

#[cfg(feature = "plutus_debug")]
use log::info;

pub(crate) fn vanishing_expressions<PCS>(circuit_repr: &mut CircuitRepresentation<PCS>)
where
    PCS: ExtractPCS,
{
    let nb_vanishing_splits = circuit_repr.nb_vanishing_splits();

    // !hCommitment1 = scale xn_minus_one G1_zero + vanishingSplit{:?}", vanishing_splits_count
    // a + b
    {
        let a = ExpressionG1::Scale(
            Box::new(ExpressionG1::Zero),
            ScalarExpression::Variable(XN_MINUS_ONE_STR.to_string()),
        );
        let b = ExpressionG1::VanishingSplit(nb_vanishing_splits);
        let init_expr = ExpressionG1::Sum(Box::new(a), Box::new(b));
        circuit_repr.expressions.vanishing(h_com_str(1), init_expr);
    }

    // Render last on as vanishing_g
    // !hCommitment{:?} = scale xn_minus_one hCommitment{:?} + vanishingSplit{:?}
    // a + b
    for i in 1..(nb_vanishing_splits - 1) {
        let a = ExpressionG1::Scale(
            Box::new(ExpressionG1::Variable(h_com_str(i))),
            ScalarExpression::Variable(XN_MINUS_ONE_STR.to_string()),
        );
        let b = ExpressionG1::VanishingSplit(nb_vanishing_splits - i);
        let loop_expr = ExpressionG1::Sum(Box::new(a), Box::new(b));
        circuit_repr
            .expressions
            .vanishing(h_com_str(i + 1), loop_expr);
    }

    // !vanishing_g = scale xn_minus_one hCommitment{} + vanishingSplit1; nb_vanishing_splits - 1
    // a + b
    {
        let a = ExpressionG1::Scale(
            Box::new(ExpressionG1::Variable(h_com_str(nb_vanishing_splits - 1))),
            ScalarExpression::Variable(XN_MINUS_ONE_STR.to_string()),
        );
        let b = ExpressionG1::VanishingSplit(1);
        let g_expr = ExpressionG1::Sum(Box::new(a), Box::new(b));
        circuit_repr
            .expressions
            .vanishing(VANISH_G_STR.to_string(), g_expr);
    }
}
