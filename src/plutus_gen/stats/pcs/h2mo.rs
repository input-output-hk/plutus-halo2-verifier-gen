use super::super::circuit_statistics::CircuitStatistics;
use super::PcsEstimate;
use blstrs::Bls12;
use halo2_proofs::poly::kzg::KZGCommitmentScheme;

pub(crate) struct H2MO;

impl PcsEstimate for KZGCommitmentScheme<Bls12> {
    const NUM_POINT_SETS: usize = H2MO::NUM_POINT_SETS;
    fn pcs_type() -> super::PCSType {
        H2MO::pcs_type()
    }
    fn read_transcript(stats: &mut CircuitStatistics) {
        H2MO::read_transcript(stats)
    }
    fn compute_opening(
        stats: &mut CircuitStatistics,
        nb_advice: usize,
        nb_fixed: usize,
        nb_permutations: usize,
        nb_lookups: usize,
        max_commitments_per_set: usize,
    ) {
        H2MO::compute_opening(
            stats,
            nb_advice,
            nb_fixed,
            nb_permutations,
            nb_lookups,
            max_commitments_per_set,
        )
    }
}

impl PcsEstimate for H2MO {
    const NUM_POINT_SETS: usize = 3;

    fn pcs_type() -> super::PCSType {
        super::PCSType::Halo2MultiOpen
    }

    fn read_transcript(stats: &mut CircuitStatistics) {
        stats.squeeze_challenge(); // x1
        stats.squeeze_challenge(); // x2
        stats.read_point(); // f_commitment
        stats.squeeze_challenge(); // x3
        (0..Self::NUM_POINT_SETS).for_each(|_| stats.read_scalar()); // q_evals
        stats.squeeze_challenge(); // x4
        stats.read_point(); // pi_term
    }

    fn compute_opening(
        stats: &mut CircuitStatistics,
        _nb_advice: usize,
        _nb_fixed: usize,
        _nb_permutations: usize,
        _nb_lookups: usize,
        max_commitments_per_set: usize,
    ) {
        // Powers of x4 (one per point set + 1)
        (2..=Self::NUM_POINT_SETS + 1).for_each(|_| stats.mul_scalar());
        // Powers of x1 (one per max commitments per set)
        (2..=max_commitments_per_set).for_each(|_| stats.mul_scalar());
    }
}
