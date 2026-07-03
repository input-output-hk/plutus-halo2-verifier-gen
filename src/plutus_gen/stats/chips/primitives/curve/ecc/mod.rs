pub(crate) use crate::plutus_gen::stats::chips::curve::FieldEmulationParams;

mod weierstrass;
pub(crate) use weierstrass::{WeierstrassChip, WeierstrassChipTrait, WeierstrassEmulationParams};

mod edwards;
pub(crate) use edwards::{EdwardsChip, EdwardsChipTrait, EdwardsEmulationParams};
