use crate::plutus_gen::stats::{arguments::permutation::nb_perm_commitments_vk, pcs::PcsEstimate};

/// Estimates the verification key size in bytes (compressed G1 elements only).
/// Does not include the SRS or PCS parameters.
///
/// - `nb_fixed` is the number of fixed wires, including selectors.
/// - `nb_copy_constrained` is the number of columns that are copy-constrained and thus,
///  participate in the permutation check.
pub(crate) fn estimate_vk_size<PCS: PcsEstimate>(
    nb_copy_constrained: usize,
    nb_fixed: usize,
) -> usize {
    if nb_copy_constrained == 0 || nb_fixed == 0 {
        return 0;
    }

    10 + 48 * (nb_fixed + nb_perm_commitments_vk(nb_copy_constrained) + PCS::nb_commitments_vk())
}
