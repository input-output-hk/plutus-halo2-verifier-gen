use super::data::CircuitConfig;
use super::pcs::PcsEstimate;
use crate::plutus_gen::stats::chips::SupportedChips;
use crate::plutus_gen::stats::data::CircuitStatistics;

pub(crate) mod build;
pub(crate) mod proof;
pub(crate) mod verifier;
pub(crate) mod vk;

use build::process;
use proof::estimate_proof_size;
use verifier::estimate_verifier_code;
use vk::estimate_vk_size;

pub fn proof_size<PCS>(
    nb_public_inputs: usize,
    nb_committed_instances: usize,
    extra: CircuitConfig,
    used_chips: &[SupportedChips],
) -> usize
where
    PCS: PcsEstimate,
{
    let processed = process::<PCS>(nb_public_inputs, nb_committed_instances, extra, used_chips);
    estimate_proof_size::<PCS>(
        nb_committed_instances,
        processed.nb_advice,
        processed.lookup_args.len(),
        processed.trashcan_args.len(),
        processed.circuit_degree,
        processed.nb_copy_constrained,
        processed.nb_advice_fixed_evaluations,
        processed.nb_point_sets,
    )
}

pub fn vk_size<PCS>(
    nb_public_inputs: usize,
    nb_committed_instances: usize,
    extra: CircuitConfig,
    used_chips: &[SupportedChips],
) -> usize
where
    PCS: PcsEstimate,
{
    let processed = process::<PCS>(nb_public_inputs, nb_committed_instances, extra, used_chips);

    estimate_vk_size::<PCS>(processed.nb_copy_constrained, processed.nb_fixed)
}

pub fn verifier_stats<PCS>(
    nb_public_inputs: usize,
    nb_committed_instances: usize,
    extra: CircuitConfig,
    used_chips: &[SupportedChips],
) -> CircuitStatistics
where
    PCS: PcsEstimate,
{
    let processed = process::<PCS>(nb_public_inputs, nb_committed_instances, extra, used_chips);

    estimate_verifier_code::<PCS>(processed)
}
