use super::super::{Chip, SupportedChips};

pub(crate) struct VerifierGadget;

impl Chip for VerifierGadget {
    fn chip_deps() -> Vec<SupportedChips> {
        vec![
            SupportedChips::Poseidon,
            SupportedChips::WeierstrassBls12381,
        ]
    }

    fn nr_pow2range() -> usize {
        // NB_ARITH_COLS - 1
        4
    }
}
