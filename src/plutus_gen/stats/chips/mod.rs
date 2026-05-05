use super::circuit_statistics::CircuitStatistics;

pub(crate) mod arith;
pub(crate) use arith::Arith;

/// A chip available in the IOHK halo2 gadget library.
pub(crate) trait Chip {
    /// Additional advice columns this chip contributes (max'd across chips, not summed).
    const NB_ADVICE: usize;
    /// Additional fixed columns this chip contributes (max'd across chips, not summed).
    const NB_FIXED: usize;
    /// Number of gate constraint equations this chip contributes to the expression combiner.
    const NB_EQUATIONS: usize;
    /// Degree of the gate polynomial (determines the constraint system degree).
    const DEGREE: usize;
    /// Number of distinct rotation points the chip's gate polynomial touches.
    const NB_EVAL_POINTS: usize;
    /// Extra scalar operations per lookup input/table expression beyond the theta-compression
    /// wrapper (add + mul). Set to 0 for single-column lookups; higher for polynomial inputs.
    const NB_LOOKUP_EXPRESSION_OPS: usize;

    fn lookup_tables(&self) -> &'static [LookupTable];
    fn update_stats(&self, stats: &mut CircuitStatistics);
}

/// A lookup table used by one or more chips.
#[derive(Hash, Eq, PartialEq)]
pub(crate) enum LookupTable {}
