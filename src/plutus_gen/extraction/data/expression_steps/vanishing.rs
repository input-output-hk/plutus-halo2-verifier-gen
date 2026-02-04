use super::super::{CircuitRepresentation, ExpressionG1, ScalarExpression, constants::*};

#[cfg(feature = "plutus_debug")]
use log::info;

impl CircuitRepresentation {
    pub fn vanishing_expressions(&mut self) {
        // let mut terms = Vec::new();

        let nb_vanishing_splits = self.nb_vanishing_splits();

        // Raphael: Not sure this works for more splits
        // !hCommitment1 = scale xn_one G1_zero + vanishingSplit{:?}", nb_vanishing_splits
        // a + b
        {
            let a = ExpressionG1::Scale(
                Box::new(ExpressionG1::Zero),
                ScalarExpression::Variable(XN_STR.to_string()),
            );
            let b = ExpressionG1::VanishingSplit(nb_vanishing_splits);
            let init_expr = ExpressionG1::Sum(Box::new(a), Box::new(b));
            // terms.push((h_com_str(1), term));
            self.expressions.vanishing(h_com_str(1), init_expr);
        }

        // render last on as vanishing_g
        // !hCommitment{:?} = scale xn hCommitment{:?} + vanishingSplit{:?}
        // a + b
        for i in 1..(nb_vanishing_splits - 1) {
            let a = ExpressionG1::Scale(
                Box::new(ExpressionG1::Variable(h_com_str(i))),
                ScalarExpression::Variable(XN_STR.to_string()),
            );
            let b = ExpressionG1::VanishingSplit(nb_vanishing_splits - i);
            let loop_expr = ExpressionG1::Sum(Box::new(a), Box::new(b));

            // terms.push((h_com_str(i + 1), term));
            self.expressions.vanishing(h_com_str(i + 1), loop_expr);
        }

        // !vanishing_g = scale xn hCommitment{} + vanishingSplit1; nb_vanishing_splits - 1
        // a + b
        {
            let a = ExpressionG1::Scale(
                Box::new(ExpressionG1::Variable(h_com_str(nb_vanishing_splits - 1))),
                ScalarExpression::Variable(XN_STR.to_string()),
            );
            let b = ExpressionG1::VanishingSplit(1);
            let g_expr = ExpressionG1::Sum(Box::new(a), Box::new(b));
            self.expressions.vanishing(VANISH_G_STR.to_string(), g_expr);
        }
    }
}
