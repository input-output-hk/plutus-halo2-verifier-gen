use super::super::circuit_statistics::CircuitStatistics;
use super::{Chip, LookupTable};

/// Combined Rescue + Schnorr sidechain chip (AtmsVerifierGate).
///
/// Merges [`RescueSidechain`] (MainGate, 5 advice / 13 fixed / degree 6) with
/// the ECC constraints added by [`SchnorrSidechain`] (2 extra advice / degree 7).
///
/// Total: 7 advice, 13 fixed, degree 7, 5 gate equations.
pub(crate) struct SchnorrRescueSidechain;

impl Chip for SchnorrRescueSidechain {
    const NB_ADVICE: usize = 7; // 5 MainGate + 2 ECC (b, scalar_mul)
    const NB_FIXED: usize = 16; // MainGate selectors; ECC reuses them
    const NB_EQUATIONS: usize = 5; // 1 Rescue cap_gate + 2 CondAdd + 2 WitnessPoint
    const DEGREE: usize = 7; // CondAdd is degree 7
    const NB_EVAL_POINTS: usize = 2; // Rescue uses Rotation::next()
    const NB_LOOKUP_EXPRESSION_OPS: usize = 0;
    const LOOKUP_TABLES: &'static [LookupTable] = &[];

    fn update_stats(&self, stats: &mut CircuitStatistics) {
        // Rescue (MainGate cap_gate): 30 mul, 12 add
        (0..30).for_each(|_| stats.mul_scalar());
        (0..12).for_each(|_| stats.add_scalar());

        // Schnorr ECC (CondAdd + WitnessPoint): 36 mul, 16 add, 9 neg, 8 from_int
        (0..36).for_each(|_| stats.mul_scalar());
        (0..16).for_each(|_| stats.add_scalar());
        (0..9).for_each(|_| stats.neg_scalar());
        (0..8).for_each(|_| stats.from_int_scalar());
    }
}
