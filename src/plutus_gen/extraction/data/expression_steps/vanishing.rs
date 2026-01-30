use super::super::{
    CircuitRepresentation, ExpressionG1, ProofExtractionSteps, ScalarExpression, constants::*,
};

use midnight_curves::BlsScalar as Scalar;

#[cfg(feature = "plutus_debug")]
use log::info;

pub fn vanishing_expressions(
    circuit_description: &CircuitRepresentation,
) -> Vec<(String, ExpressionG1<Scalar>)> {
    let mut terms = Vec::new();

    let nb_vanishing_splits = circuit_description
        .proof_extraction_steps
        .iter()
        .filter(|e| matches!(e, ProofExtractionSteps::VanishingSplit))
        .count();

    // Raphael: Not sure this works for more splits
    // !hCommitment1 = scale xn_minus_one G1_zero + vanishingSplit{:?}", nb_vanishing_splits
    // a + b
    let a = ExpressionG1::Scale(
        Box::new(ExpressionG1::Zero),
        ScalarExpression::Variable(XN_MINUS_ONE_STR.to_string()),
    );
    let b = ExpressionG1::VanishingSplit(nb_vanishing_splits);
    let term = ExpressionG1::Sum(Box::new(a), Box::new(b));
    terms.push((h_com_str(1), term));

    for i in 1..(nb_vanishing_splits - 1) {
        // render last on as vanishing_g
        // !hCommitment{:?} = scale xn_minus_one hCommitment{:?} + vanishingSplit{:?}
        // a + b
        let a = ExpressionG1::Scale(
            Box::new(ExpressionG1::Variable(h_com_str(i))),
            ScalarExpression::Variable(XN_MINUS_ONE_STR.to_string()),
        );
        let b = ExpressionG1::VanishingSplit(nb_vanishing_splits - i);
        let term = ExpressionG1::Sum(Box::new(a), Box::new(b));

        terms.push((h_com_str(i + 1), term));
    }

    // !vanishing_g = scale xn_minus_one hCommitment{} + vanishingSplit1; nb_vanishing_splits - 1
    // a + b

    let a = ExpressionG1::Scale(
        Box::new(ExpressionG1::Variable(h_com_str(nb_vanishing_splits - 1))),
        ScalarExpression::Variable(XN_MINUS_ONE_STR.to_string()),
    );
    let b = ExpressionG1::VanishingSplit(1);
    let term = ExpressionG1::Sum(Box::new(a), Box::new(b));
    terms.push((VANISH_G_STR.to_string(), term));

    terms
}
