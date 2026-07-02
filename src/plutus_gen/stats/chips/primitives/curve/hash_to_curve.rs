use super::super::super::{Chip, SupportedChips};

/// HashToCurve gadget for Jubjub.
/// It is a gadget and does not need any additional columns or arguments.
pub(crate) struct HashToCurve;

impl Chip for HashToCurve {
    fn chip_deps() -> Vec<SupportedChips> {
        vec![SupportedChips::Poseidon, SupportedChips::EdwardsJubjub]
    }
}
