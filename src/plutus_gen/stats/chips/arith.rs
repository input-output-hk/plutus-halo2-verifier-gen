use super::super::circuit_statistics::CircuitStatistics;
use super::{Chip, LookupTable};

/// Standard arithmetic gate: `ql·l + qr·r + qm·l·r + qc + qo·o = 0`
pub(crate) struct Arith;

impl Chip for Arith {
    const NB_ADVICE: usize = 3;
    const NB_FIXED: usize = 4;
    const NB_EQUATIONS: usize = 1;
    const DEGREE: usize = 3;
    const NB_EVAL_POINTS: usize = 1;
    const NB_LOOKUP_EXPRESSION_OPS: usize = 0;

    fn lookup_tables(&self) -> &'static [LookupTable] {
        &[]
    }

    fn update_stats(&self, stats: &mut CircuitStatistics) {
        // ql·l + qr·r + qm·l·r + qc + qo·o
        (0..5).for_each(|_| stats.mul_scalar());
        (0..4).for_each(|_| stats.add_scalar());
    }
}
