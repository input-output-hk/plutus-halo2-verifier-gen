pub(crate) mod gwc19;
pub(crate) mod h2mo;

pub(crate) use gwc19::GWC19;
pub(crate) use h2mo::H2MO;

use super::circuit_statistics::CircuitStatistics;

pub(crate) enum PCSType {
    Halo2MultiOpen,
    GWC19,
}

pub trait PcsEstimate {
    const NUM_POINT_SETS: usize;
    fn pcs_type() -> PCSType;
    fn read_transcript(stats: &mut CircuitStatistics);
    fn compute_opening(
        stats: &mut CircuitStatistics,
        nb_advice: usize,
        nb_fixed: usize,
        nb_permutations: usize,
        nb_lookups: usize,
        max_commitments_per_set: usize,
    );
}
