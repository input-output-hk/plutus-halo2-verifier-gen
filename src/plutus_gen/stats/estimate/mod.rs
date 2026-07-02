use super::data::CircuitConfig;
use super::pcs::{H2MO, PcsEstimate};
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

/// All size and operation-count estimates for a circuit, computed in a single pass.
///
/// Structural fields (nb_adv, nb_cc, …) reflect the merged result of all selected chips
/// plus the extra columns from `CircuitConfig`. Proof breakdown fields (bc_*, bs_*) are
/// the per-argument commit/scalar counts that sum to nb_comms and nb_scalars.
/// Verifier-op fields are exact counts for the given pi and ci.
#[derive(Default, serde::Serialize)]
pub struct AllEstimates {
    // ── Sizes ──────────────────────────────────────────────────────────────────
    pub proof_size: usize,
    pub vk_size: usize,
    pub input_size: usize,
    // ── Structural (needed by the UI for breakdown display) ────────────────────
    pub degree: usize,
    pub nb_adv: usize,
    pub nb_fix: usize,
    pub nb_cc: usize,
    pub nb_lkp: usize,
    pub nb_trash: usize,
    pub nb_gates: usize,
    pub nb_evals: usize,
    pub perm_chunks: usize,
    pub nb_point_sets: usize,
    pub nb_comms: usize,
    pub nb_scalars: usize,
    pub nb_pi: usize,
    pub nb_ci: usize,
    // ── Proof breakdown — commitments ──────────────────────────────────────────
    pub bc_advice: usize,
    pub bc_perm: usize,
    pub bc_trash: usize,
    pub bc_vanish: usize,
    pub bc_lookup: usize,
    pub bc_pcs: usize,
    // ── Proof breakdown — scalars ──────────────────────────────────────────────
    pub bs_evals: usize,
    pub bs_perm: usize,
    pub bs_trash: usize,
    pub bs_vanish: usize,
    pub bs_lookup: usize,
    pub bs_pcs: usize,
    // ── Verifier operation counts ──────────────────────────────────────────────
    pub neg_scalar: usize,
    pub add_scalar: usize,
    pub sub_scalar: usize,
    pub mul_scalar: usize,
    pub inv_scalar: usize,
    pub pow_scalar: usize,
    pub from_int_scalar: usize,
    pub from_bytes_scalar: usize,
    pub to_bytes_scalar: usize,
    pub add_point: usize,
    pub mul_point: usize,
    pub decompress_point: usize,
    pub compress_point: usize,
    pub from_bytes_point: usize,
    pub msm: Vec<usize>,
    pub miller_loop: usize,
    pub pairing: usize,
    /// One entry per Fiat-Shamir squeeze call; the value is the transcript size (bytes) absorbed.
    pub hash: Vec<usize>,
}

/// Computes proof size, VK size, and verifier operation counts in a single `process()` call.
pub fn all_estimates(
    nb_public_inputs: usize,
    nb_committed_instances: usize,
    recursion: bool,
    extra: CircuitConfig,
    used_chips: &[SupportedChips],
) -> AllEstimates {
    let processed = process::<H2MO>(
        nb_public_inputs,
        nb_committed_instances,
        recursion,
        extra,
        used_chips,
    );

    let nb_advice = processed.nb_advice;
    if nb_advice == 0 {
        return AllEstimates {
            nb_pi: nb_public_inputs,
            nb_ci: nb_committed_instances,
            input_size: nb_public_inputs * 32 + nb_committed_instances * 48,
            ..Default::default()
        };
    }

    let nb_fixed = processed.nb_fixed;
    let nb_cc = processed.nb_copy_constrained;
    let degree = processed.circuit_degree;
    let nb_lkp = processed.lookup_args.len();
    let nb_trash = processed.trashcan_args.len();
    let nb_evals = processed.nb_advice_fixed_evaluations;
    let nb_gates = processed.gate_args.len();
    let nb_point_sets = processed.nb_point_sets;
    let nb_pi = processed.nb_public_inputs;
    let nb_ci = processed.nb_committed_instances;

    // ── Proof breakdown ───────────────────────────────────────────────────────
    // degree >= 3 whenever nb_advice > 0 (minimum circuit degree)
    let perm_chunks = if nb_cc > 0 {
        nb_cc.div_ceil(degree - 2)
    } else {
        0
    };
    let bc_advice = nb_advice;
    let bc_perm = perm_chunks;
    let bc_trash = nb_trash;
    let bc_vanish = degree; // 1 random + (degree-1) splits = degree
    let bc_lookup = 3 * nb_lkp;
    let bc_pcs = H2MO::nb_commitments();

    let bs_evals = nb_evals + usize::from(nb_ci > 0);
    let bs_perm = if nb_cc > 0 {
        nb_cc + 3 * perm_chunks - 1
    } else {
        0
    };
    let bs_trash = nb_trash;
    let bs_vanish = 1; // vanishing random eval
    let bs_lookup = 5 * nb_lkp;
    let bs_pcs = H2MO::nb_evaluations(nb_point_sets);

    let nb_comms = bc_advice + bc_perm + bc_trash + bc_vanish + bc_lookup + bc_pcs;
    let nb_scalars = bs_evals + bs_perm + bs_trash + bs_vanish + bs_lookup + bs_pcs;
    let proof_size = nb_comms * 48 + nb_scalars * 32;
    let vk_size = estimate_vk_size::<H2MO>(nb_cc, nb_fixed);
    let input_size = nb_pi * 32 + nb_ci * 48;

    // ── Verifier stats (consumes `processed`) ─────────────────────────────────
    let stats = estimate_verifier_code::<H2MO>(processed);

    AllEstimates {
        proof_size,
        vk_size,
        input_size,
        degree,
        nb_adv: nb_advice,
        nb_fix: nb_fixed,
        nb_cc,
        nb_lkp,
        nb_trash,
        nb_gates,
        nb_evals,
        perm_chunks,
        nb_point_sets,
        nb_comms,
        nb_scalars,
        nb_pi,
        nb_ci,
        bc_advice,
        bc_perm,
        bc_trash,
        bc_vanish,
        bc_lookup,
        bc_pcs,
        bs_evals,
        bs_perm,
        bs_trash,
        bs_vanish,
        bs_lookup,
        bs_pcs,
        neg_scalar: stats.neg_scalar,
        add_scalar: stats.add_scalar,
        sub_scalar: stats.sub_scalar,
        mul_scalar: stats.mul_scalar,
        inv_scalar: stats.inv_scalar,
        pow_scalar: stats.pow_scalar,
        from_int_scalar: stats.from_int_scalar,
        from_bytes_scalar: stats.from_bytes_scalar,
        to_bytes_scalar: stats.to_bytes_scalar,
        add_point: stats.add_point,
        mul_point: stats.mul_point,
        decompress_point: stats.decompress_point,
        compress_point: stats.compress_point,
        from_bytes_point: stats.from_bytes_point,
        msm: stats.msm,
        miller_loop: stats.miller_loop,
        pairing: stats.pairing,
        hash: stats.hash,
    }
}

pub fn proof_size(
    nb_public_inputs: usize,
    nb_committed_instances: usize,
    recursion: bool,
    extra: CircuitConfig,
    used_chips: &[SupportedChips],
) -> usize {
    let processed = process::<H2MO>(
        nb_public_inputs,
        nb_committed_instances,
        recursion,
        extra,
        used_chips,
    );
    estimate_proof_size::<H2MO>(
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

pub fn vk_size(
    nb_public_inputs: usize,
    nb_committed_instances: usize,
    recursion: bool,
    extra: CircuitConfig,
    used_chips: &[SupportedChips],
) -> usize {
    let processed = process::<H2MO>(
        nb_public_inputs,
        nb_committed_instances,
        recursion,
        extra,
        used_chips,
    );

    estimate_vk_size::<H2MO>(processed.nb_copy_constrained, processed.nb_fixed)
}

pub fn verifier_stats(
    nb_public_inputs: usize,
    nb_committed_instances: usize,
    recursion: bool,
    extra: CircuitConfig,
    used_chips: &[SupportedChips],
) -> CircuitStatistics {
    let processed = process::<H2MO>(
        nb_public_inputs,
        nb_committed_instances,
        recursion,
        extra,
        used_chips,
    );

    estimate_verifier_code::<H2MO>(processed)
}
