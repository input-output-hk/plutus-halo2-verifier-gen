// Shared verifier cost formula.
// Loaded by cost.html and chips.html.
// Depends on CHIP_PROFILES being defined first (chip_profiles.js).
//
// compute(p, chip) → result object with proof_size, vk_size, nb_cc, …
//
// p fields:
//   pi  — number of public inputs
//   ci  — number of committed instances
//   adv — extra advice columns (beyond chip)
//   fix — extra fixed columns
//   sel — extra selector columns
//   lkp — extra lookup arguments
//   eva — extra evaluation queries (clamped to valid range)
//   deg — extra degree hint
function compute(p, chip) {
  chip = chip || CHIP_PROFILES.none;
  const nb_pi = p.pi;
  const nb_ci = p.ci;

  // Total advice: chip advice + extra advice columns
  const nb_adv = chip.adv + p.adv;
  // Total fixed columns in VK: chip fixed + extra fixed + selectors
  const nb_fix = chip.fixed_vk + p.fix + p.sel;
  // Total lookup args
  const nb_lkp = chip.lookups + p.lkp;
  // Trash arguments (from chips only)
  const nb_trash = chip.trash;
  const deg_hint = p.deg;

  // Copy-constrained columns:
  //   1 instance col if pi > 0 or ci > 0
  //   chip.chip_cc = chip's own cc cols (advice + fixed that are cc, excl. instance)
  //   all extra advice are cc; extra fixed are NOT cc
  const cc_pi = (nb_pi > 0 || nb_ci > 0) ? 1 : 0;
  const nb_cc = cc_pi + chip.chip_cc + p.adv;

  // Circuit degree
  const has_perm    = nb_cc > 0;
  const has_lookups = nb_lkp > 0;
  const hasCircuit  = nb_adv > 0 || nb_cc > 0 || nb_lkp > 0 || chip.degree > 0 || deg_hint > 0;
  const degree = Math.max(
    deg_hint,
    has_perm    ? 3 : 0,
    has_lookups ? 5 : 0,
    chip.degree,
    hasCircuit  ? 3 : 0   // min degree 3 when there's an actual circuit
  );

  // Evaluations: chip evals + extra.
  // Floor = nb_adv (each advice col queried at least once); cap = 2*(adv+fix+sel).
  const evaMax = 2 * (p.adv + p.fix + p.sel);
  const nb_extra_evals = Math.max(p.adv, Math.min(p.eva, evaMax));
  const nb_eval = chip.evals + nb_extra_evals;

  // ── Permutation ──────────────────────────────────────────────────
  const perm_chunks    = nb_cc > 0 ? Math.ceil(nb_cc / (degree - 2)) : 0;
  const bc_perm        = perm_chunks;
  const bs_perm_common = nb_cc;
  const bs_perm_cross  = nb_cc > 0 ? 3 * perm_chunks - 1 : 0;
  const bs_perm        = bs_perm_common + bs_perm_cross;

  // ── Vanishing ────────────────────────────────────────────────────
  const bc_vanish = 1 + (degree - 1);   // = degree; naturally 0 when degree=0
  const bs_vanish = degree > 0 ? 1 : 0;

  // ── Lookup (PlookUp) ─────────────────────────────────────────────
  const bc_lookup = 3 * nb_lkp;
  const bs_lookup = 5 * nb_lkp;

  // ── Trash arguments (1 commit + 1 eval each) ─────────────────────
  const bc_trash = nb_trash;
  const bs_trash = nb_trash;

  // ── PCS (H2MO) ───────────────────────────────────────────────────
  const has_curr_next      = has_perm || has_lookups;
  const has_curr_next_last = perm_chunks > 1;
  const has_prev_curr      = has_lookups;
  const nb_point_sets = 1
    + (has_curr_next      ? 1 : 0)
    + (has_curr_next_last ? 1 : 0)
    + (has_prev_curr      ? 1 : 0);

  const bc_pcs = degree > 0 ? 2 : 0;
  const bs_pcs = degree > 0 ? Math.max(nb_point_sets, 3) : 0;

  // ── Proof size ───────────────────────────────────────────────────
  const bc_advice = nb_adv;
  const bs_evals  = nb_eval + (nb_ci > 0 ? 1 : 0);

  const nb_comms   = bc_advice + bc_perm + bc_trash + bc_vanish + bc_lookup + bc_pcs;
  const nb_scalars = bs_evals  + bs_perm + bs_trash + bs_vanish + bs_lookup + bs_pcs;
  const proof_size = nb_comms * 48 + nb_scalars * 32;

  // ── VK size ──────────────────────────────────────────────────────
  const nb_vk_comms = nb_fix + nb_cc;
  const vk_size = nb_vk_comms > 0 ? 10 + 48 * nb_vk_comms : 0;

  // ── Input size ───────────────────────────────────────────────────
  const input_size = nb_pi * 32 + nb_ci * 48;

  const nb_gates = chip.gates;

  return {
    proof_size, vk_size, input_size, degree,
    nb_cc, nb_gates, perm_chunks, nb_point_sets,
    nb_comms, nb_scalars,
    bc_advice, bc_perm, bc_trash, bc_vanish, bc_lookup, bc_pcs,
    bs_evals,  bs_perm, bs_trash, bs_vanish, bs_lookup, bs_pcs,
    nb_fix, nb_adv, nb_lkp, nb_trash,
    nb_pi, nb_ci,
  };
}

// ─── VERIFIER OPERATION COUNTS ────────────────────────────────────────────────
//
// computeVerifierOps(p, chip) adjusts the chip's baseline verifier stats
// (precomputed at pi=1, ci=0) for the current pi and ci slider values.
//
// Changes that are handled interactively:
//   • pi: absorb_vk_and_inputs adds pi to_bytes_scalar (one per public input);
//         process_pes runs lagrange_polynomial_basis(pi+1) + inner_product(pi+1)
//         + (pi+1) rotate_omega when pi>0, or one from_int_scalar when pi=0.
//         Delta per additional pi (for pi≥1): +1 to_bytes_s, +1 pow, +7 mul, +1 sub, +1 add.
//         Transition pi=0→pi=1 is handled separately (subtract lagrange(2) baseline, add from_int).
//   • ci: process_pes reads one extra scalar when ci>0 (committed-instance evaluation).
//
// Extra advice/lookup/selector columns change the permutation structure and
// PCS commitment map — those require a CLI run for exact counts.
//
// Derivation of the per-pi delta:
//   lagrange_polynomial_basis(n):
//     mul = 1 + 3*(n-1) + 2*n = 5n-2,  sub = n,  inv = 1
//   inner_product(n): add = n, mul = n
//   rotate_omega: pow = 1, mul = 1
//   Total at pi=k (k≥1): 2k pow + (5k+6k-2+k) mul + k sub + k add + 1 inv
//                       = 2k pow + (12k-2) mul + k sub + k add + 1 inv
//   Delta per k: +2 pow … wait — rotate_omega is called (pi+1) times total.
//   At pi=1: 2 rotate_omega + lagrange_basis(2) + inner_product(2)
//     = 2pow + 2mul + (5*2-2)mul + 2sub + 1inv + 2add + 2mul
//     = 2pow + 12mul + 2sub + 1inv + 2add
//   At pi=2: 3 rotate_omega + lagrange_basis(3) + inner_product(3)
//     = 3pow + 3mul + (5*3-2)mul + 3sub + 1inv + 3add + 3mul
//     = 3pow + 19mul + 3sub + 1inv + 3add
//   Delta (pi=2 minus pi=1): +1pow, +7mul, +1sub, +0inv, +1add  ✓ (constant)
//
function computeVerifierOps(p, chip) {
  const v = chip.verifier;
  if (!v || v.miller_loop === 0) {
    // No circuit (none chip or baseline is zero) — return zeros.
    return { neg:0, add:0, sub:0, mul:0, inv:0, pow:0, from_int:0,
             from_bytes_s:0, to_bytes_s:0, add_p:0, mul_p:0,
             decomp:0, comp:0, from_bytes_p:0, msm:[], miller_loop:0, pairing:0 };
  }

  // Start from the pi=1, ci=0 baseline.
  let neg        = v.neg,        add  = v.add,        sub = v.sub;
  let mul        = v.mul,        inv  = v.inv,        pow = v.pow;
  let from_int   = v.from_int,   from_bytes_s = v.from_bytes_s;
  let to_bytes_s = v.to_bytes_s;
  let add_p      = v.add_p,      mul_p = v.mul_p;
  let decomp     = v.decomp,     comp  = v.comp,  from_bytes_p = v.from_bytes_p;
  const msm      = v.msm.slice(); // copy

  const pi = p.pi, ci = p.ci;

  // ── pi adjustment ─────────────────────────────────────────────────
  if (pi === 0) {
    // Baseline has pi=1: remove lagrange(2)+inner_product(2)+2×rotate_omega, add from_int.
    // lagrange_polynomial_basis(2): mul=8, sub=2, inv=1
    // inner_product(2): add=2, mul=2
    // 2×rotate_omega: pow=2, mul=2
    pow       -= 2;
    mul       -= 12;   // 8 + 2 + 2
    sub       -= 2;
    inv       -= 1;
    add       -= 2;
    to_bytes_s -= 1;   // one fewer absorbed public input
    from_int  += 1;    // the else branch: stats.from_int_scalar()
  } else if (pi > 1) {
    // Add (pi-1) increments on top of the pi=1 baseline.
    const d = pi - 1;
    to_bytes_s += d;
    pow        += d;
    mul        += 7 * d;
    sub        += d;
    add        += d;
  }
  // pi === 1: baseline is exact, no adjustment needed.

  // ── ci adjustment ─────────────────────────────────────────────────
  // Baseline is ci=0. When ci>0, process_pes reads one extra scalar.
  if (ci > 0) {
    from_bytes_s += 1;
  }

  return { neg, add, sub, mul, inv, pow, from_int,
           from_bytes_s, to_bytes_s, add_p, mul_p,
           decomp, comp, from_bytes_p, msm,
           miller_loop: v.miller_loop, pairing: v.pairing };
}
