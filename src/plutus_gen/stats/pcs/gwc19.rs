//! Symbolic GWC19 MSM construction — a 1:1 analogue of `multi_prepare` from
//! `src/poly/gwc_kzg/mod.rs` in the IOHK halo2 fork, translated to build an
//! `MsmOperations` description instead of evaluating it numerically.
use super::super::circuit_statistics::CircuitStatistics;
use super::PcsEstimate;
use crate::plutus_gen::extraction::data::{
    MsmOperations, Query, RotationDescription, ScalarOperation,
};
use blstrs::Bls12;
use halo2_proofs::poly::gwc_kzg::GwcKZGCommitmentScheme;

impl PcsEstimate for GwcKZGCommitmentScheme<Bls12> {
    const NUM_POINT_SETS: usize = GWC19::NUM_POINT_SETS;
    fn pcs_type() -> super::PCSType {
        GWC19::pcs_type()
    }
    fn read_transcript(stats: &mut CircuitStatistics) {
        GWC19::read_transcript(stats)
    }
    fn compute_opening(
        stats: &mut CircuitStatistics,
        nb_advice: usize,
        nb_fixed: usize,
        nb_permutations: usize,
        nb_lookups: usize,
        max_commitments_per_set: usize,
    ) {
        GWC19::compute_opening(
            stats,
            nb_advice,
            nb_fixed,
            nb_permutations,
            nb_lookups,
            max_commitments_per_set,
        )
    }
}

pub(crate) struct GWC19;

/// Queries assumed: advice+fixed+perms+lookups×3 at x,
///                  perms+lookups at x·ω, lookups at x·ω⁻¹
impl PcsEstimate for GWC19 {
    const NUM_POINT_SETS: usize = 3;
    fn pcs_type() -> super::PCSType {
        super::PCSType::GWC19
    }

    fn read_transcript(stats: &mut CircuitStatistics) {
        stats.squeeze_challenge(); // v
        (0..Self::NUM_POINT_SETS).for_each(|_| stats.read_point()); // witnesses
        stats.squeeze_challenge(); // u
    }

    fn compute_opening(
        stats: &mut CircuitStatistics,
        nb_advice: usize,
        nb_fixed: usize,
        nb_permutations: usize,
        nb_lookups: usize,
        _max_commitments_per_set: usize,
    ) {
        let q_curr = nb_advice + nb_fixed + nb_permutations + 3 * nb_lookups;
        let q_next = nb_permutations + nb_lookups;
        let q_prev = nb_lookups;
        let q_total = q_curr + q_next + q_prev;

        // Left MSM: one witness per rotation point, scalars are precomputed u-powers
        (0..Self::NUM_POINT_SETS).for_each(|_| {
            stats.decompress_point();
            stats.scale();
            stats.add_point();
        });

        // Right MSM: after optimize_msm, multi-rotation commitments merge per key
        let right_msm_size = nb_advice + nb_fixed + nb_permutations + 3 * nb_lookups + 4;
        (0..right_msm_size).for_each(|_| {
            stats.decompress_point();
            stats.scale();
            stats.add_point();
        });

        // W1/W2 scalars: MulS(u^i, rotation) — W0 is free (u^0 = 1)
        stats.mul_scalar();
        stats.mul_scalar();
        // Merged dual-rotation elements: Add(free, MulS(u^i, v^j))
        (0..nb_permutations + 2 * nb_lookups).for_each(|_| {
            stats.add_scalar();
            stats.mul_scalar();
        });
        // AppendNegatedG1: traverses the full eval_multi tree
        if q_total > 1 {
            (1..q_total).for_each(|_| {
                stats.mul_scalar();
                stats.add_scalar();
            });
        }
        // Powers of v (max exponent = q_curr - 1)
        if q_curr > 1 {
            (2..q_curr).for_each(|_| stats.mul_scalar());
        }
        // Powers of u: u^0, u^1, u^2 → 1 mul
        stats.mul_scalar();
    }
}

/// Groups queries by their evaluation point, preserving insertion order.
pub(crate) fn group_queries_by_point(
    queries: [Vec<Query>; 6],
) -> Vec<(Vec<Query>, RotationDescription)> {
    let mut map: Vec<(RotationDescription, Vec<Query>)> = Vec::new();
    for query in queries.iter().flatten() {
        if let Some(pos) = map.iter().position(|(pt, _)| *pt == query.point) {
            map[pos].1.push(*query);
        } else {
            map.push((query.point, vec![*query]));
        }
    }
    map.into_iter().map(|(pt, qs)| (qs, pt)).collect()
}

/// Symbolic representation of v^0, v^1, v^2, … or u^0, u^1, …
pub(crate) fn powers(name: char) -> impl Iterator<Item = ScalarOperation> {
    (0..).map(move |idx| ScalarOperation::Power(name, idx))
}

/// Constructs the symbolic left (witness) and right (commitment − eval) MSMs for GWC19.
pub(crate) fn construct_msm(
    commitment_data: Vec<(Vec<Query>, RotationDescription)>,
) -> (MsmOperations, MsmOperations) {
    let w_count = commitment_data.len();

    let mut commitment_multi = MsmOperations::Empty;
    let mut eval_multi = ScalarOperation::Zero;
    let mut witness = MsmOperations::Empty;
    let mut witness_with_aux = MsmOperations::Empty;

    for ((queries_at_point, wi), power_of_u) in
        commitment_data.iter().zip(0..w_count).zip(powers('u'))
    {
        let (queries, point) = queries_at_point;
        assert!(!queries.is_empty());

        let (commitment_batch, eval_batch) = queries
            .iter()
            .zip(powers('v'))
            .map(|(query, power_of_v)| {
                assert_eq!(query.point, *point);
                let mut msm = MsmOperations::Empty;
                msm = MsmOperations::Append(Box::new(msm), power_of_v.clone(), query.commitment);
                let eval = ScalarOperation::Mul(Box::new(power_of_v), query.evaluation);
                (msm, eval)
            })
            .reduce(|(cacc, eacc), (c, e)| {
                (
                    MsmOperations::Add(Box::new(cacc.clone()), Box::new(c)),
                    ScalarOperation::Add(Box::new(eacc), Box::new(e)),
                )
            })
            .unwrap();

        let commitment_batch = MsmOperations::Scale(Box::new(commitment_batch), power_of_u.clone());
        commitment_multi =
            MsmOperations::Add(Box::new(commitment_multi), Box::new(commitment_batch));
        eval_multi = ScalarOperation::Add(
            Box::new(eval_multi),
            Box::new(ScalarOperation::MulS(
                Box::new(power_of_u.clone()),
                Box::new(eval_batch),
            )),
        );

        witness_with_aux = MsmOperations::AppendW(
            Box::new(witness_with_aux),
            ScalarOperation::MulS(
                Box::new(power_of_u.clone()),
                Box::new(ScalarOperation::Rotation(*point)),
            ),
            wi,
        );
        witness = MsmOperations::AppendW(Box::new(witness), power_of_u, wi);
    }

    let left = witness;
    let mut right = MsmOperations::Empty;
    right = MsmOperations::Add(Box::new(right), Box::new(witness_with_aux));
    right = MsmOperations::Add(Box::new(right), Box::new(commitment_multi));
    right = MsmOperations::AppendNegatedG1(Box::new(right), eval_multi);

    (left, right)
}
