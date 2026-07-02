use crate::plutus_gen::stats::{chips::ScalarExpression, data::CircuitStatistics};

// The trashcan degree is max(2, expression.degree())
pub(crate) const TRASH_DEGREE: usize = 2;

/// Returns the number of commitments the trashcan argument contributes to
/// the proof.
pub(crate) fn nb_trash_commitments(nb_trashcans: usize) -> usize {
    // one commitment per argument
    nb_trashcans
}
/// Returns the number of evaluations the trashcan argument contributes to
/// the proof.
pub(crate) fn nb_trash_evaluations(nb_trashcans: usize) -> usize {
    // one evaluation per argument
    nb_trashcans
}

// Compute the trashcan arguments
pub(crate) fn compute_trashcans(
    stats: &mut CircuitStatistics,
    trashcan_args: Vec<Vec<ScalarExpression>>,
) {
    for arg in trashcan_args {
        // Batching from 0, otherwise we could consume ScalarExpression::batch_expressions(arg)
        for exp in arg {
            stats.consume_expression(&exp);
            stats.mul_scalar();
            stats.add_scalar();
        }
        // TODO: Selector can have its own expression
        // batched_expressions - (1 - q) * trash_eval
        stats.sub_scalar();
        stats.mul_scalar();
        stats.sub_scalar();
    }
}
