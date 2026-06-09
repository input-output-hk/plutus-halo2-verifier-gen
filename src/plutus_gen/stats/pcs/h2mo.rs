use super::super::data::CircuitStatistics;
use super::{PCSType, PcsEstimate};

pub(crate) struct H2MO;

mod kzg_impl {
    use super::*;
    use midnight_curves::Bls12;
    use midnight_proofs::poly::kzg::KZGCommitmentScheme;

    impl PcsEstimate for KZGCommitmentScheme<Bls12> {
        fn pcs_type() -> super::PCSType {
            H2MO::pcs_type()
        }
        fn read_transcript(stats: &mut CircuitStatistics, nb_point_sets: usize) {
            H2MO::read_transcript(stats, nb_point_sets)
        }
        fn compute_opening(
            stats: &mut CircuitStatistics,
            halo2_commitment_data: &Vec<Vec<usize>>,
            max_commitments_per_set: usize,
            kzg_halo2_point_sets: &Vec<usize>,
            nb_point_sets: usize,
        ) {
            H2MO::compute_opening(
                stats,
                halo2_commitment_data,
                max_commitments_per_set,
                kzg_halo2_point_sets,
                nb_point_sets,
            )
        }

        fn nb_commitments_vk() -> usize {
            0
        }

        fn nb_commitments() -> usize {
            H2MO::nb_commitments()
        }

        fn nb_evaluations(nb_point_sets: usize) -> usize {
            H2MO::nb_evaluations(nb_point_sets)
        }
    }
} // mod kzg_impl

impl PcsEstimate for H2MO {
    fn pcs_type() -> super::PCSType {
        super::PCSType::Halo2MultiOpen
    }

    fn read_transcript(stats: &mut CircuitStatistics, nb_point_sets: usize) {
        // X1
        stats.squeeze_challenge();

        // X2
        stats.squeeze_challenge();

        // F commitment
        stats.read_point();

        // X3
        stats.squeeze_challenge();

        // Q polynomial evaluations on x3
        (0..nb_point_sets).for_each(|_| stats.read_scalar());

        // X4
        stats.squeeze_challenge();

        // Pi term
        stats.read_point();
    }

    fn compute_opening(
        stats: &mut CircuitStatistics,
        halo2_commitment_data: &Vec<Vec<usize>>,
        max_commitments_per_set: usize,
        kzg_halo2_point_sets: &Vec<usize>,
        nb_point_sets: usize,
    ) {
        // Compute commitment_data

        // Compute max commitment per set

        // Computing powers of x1 (max points per set)
        (0..max_commitments_per_set).for_each(|_| stats.mul_scalar()); // powers of x1

        // Computng powers of x4 (num point sets)
        (0..nb_point_sets + 1).for_each(|_| stats.mul_scalar()); // powers of x4

        // Compute Q evaluations and final commitment
        compute_q_evals(stats, &halo2_commitment_data);

        // Compute f evaluation
        compute_f_eval(stats, &kzg_halo2_point_sets);

        // Compute v evaluation
        compute_v_eval(stats, nb_point_sets);

        // Compressing commitment
        (0..2).for_each(|_| stats.add_point());
        (0..2).for_each(|_| stats.scale());
        (0..2).for_each(|_| stats.decompress_point());
    }

    fn nb_commitments_vk() -> usize {
        0
    }

    fn nb_commitments() -> usize {
        // f_commitment
        // pi_term
        2
    }

    fn nb_evaluations(nb_point_sets: usize) -> usize {
        // Nb of point sets, at least {(current), (current, next), (current, next, last)}
        // q_eval_on_x3_{}
        usize::max(nb_point_sets, 3) as usize
    }
}

fn compute_q_evals(stats: &mut CircuitStatistics, halo2_commitment_data: &Vec<Vec<usize>>) {
    let mut is_first = true;
    for commitment_set in halo2_commitment_data {
        stats.msm(commitment_set.len());
        for eval in commitment_set {
            // This is a fold so there is a difference for decompress/add/mul of 1 for the init
            // Accumulator1: let acc1 = add_g1(acc1, scale(decompress(commitment), x1Power))
            stats.decompress_point();

            // Accumulator2: if is_empty(acc2) {map(es, fn(e) { mul(e, x1Power) })} else {map2(acc2, es, fn(a, b) { add(a, mul(b, x1Power)) })}
            (0..*eval).for_each(|_| {
                stats.mul_scalar();
                if !is_first {
                    stats.add_scalar();
                }
                is_first = false;
            });
        }

        //  let acc1 = add_g1(acc1, scale(q_comms, x4Power))
        stats.add_point();
        stats.scale();
    }
}

fn compute_f_eval(stats: &mut CircuitStatistics, kzg_halo2_point_sets: &Vec<usize>) {
    // TODO: update current code when CIP 109 is merged
    // step 1: compute r_evals and demonimator for all point sets
    kzg_halo2_point_sets.iter().for_each(|nb_rot| {
        // let r_eval = lagrange_evaluation(zip(points, evals), x3)
        stats.lagrange_evaluation(*nb_rot);

        // denom
        (0..*nb_rot).for_each(|_| {
            stats.sub_scalar();
            stats.mul_scalar();
        });
    });

    // step 2: batch inverse
    // TODO when CIP-109 is implemented, inverting each element should be cheaper
    stats.batch_inversion(kzg_halo2_point_sets.len());

    // step 3: compute final result
    kzg_halo2_point_sets.iter().for_each(|_| {
        // let evaluation = mul(sub(proofQEval, r_eval), denom_inv)
        stats.mul_scalar();
        stats.sub_scalar();

        // add(mul(acc_eval, x2), evaluation)
        stats.mul_scalar();
        stats.add_scalar();
    });
}

fn compute_v_eval(stats: &mut CircuitStatistics, point_sets_indexes: usize) {
    (0..point_sets_indexes).for_each(|_| {
        stats.add_scalar();
        stats.mul_scalar();
    });
}
