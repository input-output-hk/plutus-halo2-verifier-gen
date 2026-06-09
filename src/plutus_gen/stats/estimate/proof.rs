use crate::plutus_gen::stats::{
    arguments::permutation::{nb_perm_commitments, nb_perm_evaluations},
    arguments::{
        trashcans::{nb_trash_commitments, nb_trash_evaluations},
        vanishing::{nb_vanish_commitments, nb_vanish_evaluations},
    },
    lookup::{LookupEstimate, PlookUp},
    pcs::PcsEstimate,
};

/// Estimates a lower bound for the proof size in bytes.
///
/// - `nb_committed_instances` is the number of committed instances.
/// - `nb_advice` is the number of advice wires.
/// - `nb_lookups` is the number of lookup arguments.
/// - `nb_trashcans` is the number of trashcan arguments.
/// - `circuit_degree` is the circuit degree.
/// - `nb_copy_constrained` is the number of columns that are copy-constrained and thus,
///  participate in the permutation check.
/// - `nb_evaluations` is the total number of evaluations.
/// - `nb_point_sets` is the number of distinct rotation-point groups in the multi-open PCS
/// argument; pass the result of `estimate_nb_point_sets` or supply a known value.
pub(crate) fn estimate_proof_size<PCS: PcsEstimate>(
    nb_committed_instances: usize,
    nb_advice: usize,
    nb_lookups: usize,
    nb_trashcans: usize,
    circuit_degree: usize,
    nb_copy_constrained: usize,
    nb_evaluations: usize,
    nb_point_sets: usize,
) -> usize {
    // Commitments
    // - advice commitments: 1 per advice column
    // - permutation commitments: 1 per chunks of copy-constrained columns
    // - vanishing commitments: 1 (randomness) + 1 per vanishing polynomial (that is cs_degree - 1)
    // - lookup commitments: 5 per lookup argument
    // - PCS commitments: depends on the PCS
    let nb_commitments = nb_advice
        + nb_perm_commitments(nb_copy_constrained, circuit_degree)
        + nb_trash_commitments(nb_trashcans)
        + nb_vanish_commitments(circuit_degree)
        + PlookUp::nb_commitments(nb_lookups)
        + PCS::nb_commitments();

    // Evaluations
    // - com_instance/advice/fixed evaluations: 1 per rotation
    // - permutation evaluations: 1 per chunk of copy-constrained columns, at the necessary rotations (current and next for the first chunk, current only for the rest)
    // - vanishing evaluations: 1 per vanishing polynomial, at the necessary rotations (current and next)
    // - lookup evaluations: 5 per lookup argument, at the necessary rotations (current and next)
    // - PCS evaluations: depends on the PCS, at the necessary rotations (current and next)
    let nb_scalars = nb_evaluations
        + (nb_committed_instances > 0) as usize
        + nb_perm_evaluations(nb_copy_constrained, circuit_degree)
        + nb_trash_evaluations(nb_trashcans)
        + nb_vanish_evaluations()
        + PlookUp::nb_evaluations(nb_lookups)
        + PCS::nb_evaluations(nb_point_sets);

    if nb_advice == 0 {
        return 0;
    }
    nb_commitments * 48 + nb_scalars * 32
}
