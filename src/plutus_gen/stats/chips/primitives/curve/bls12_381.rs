use crate::plutus_gen::stats::chips::curve::{fe_to_bigint_le, to_bigint};

use super::super::super::{Argument, Chip, Column, LookupTable, SupportedChips};
use super::{
    FieldEmulationParams, WeierstrassChip, WeierstrassChipTrait, WeierstrassEmulationParams,
};

use ff::PrimeField;
use midnight_circuits::ecc::curves::WeierstrassCurve;
use midnight_curves::bls12_381;
use num_bigint::BigInt;

/// Merged Weierstrass ECC, Base & Scalar Field chips for Bls12381 (foreign field, multi-limb via MEP).
// struct WeierstrassBls12381Scalar;
pub(crate) struct WeierstrassBls12381;

impl FieldEmulationParams for WeierstrassBls12381 {
    const LOG2_BASE: u32 = 56;
    const NB_LIMBS: usize = 7;
    const RC_LIMB_SIZE: usize = 15;

    fn modulus() -> BigInt {
        to_bigint(bls12_381::Fp::MODULUS)
    }

    fn moduli() -> Vec<BigInt> {
        vec![
            BigInt::from(2).pow(134),
            BigInt::from(2).pow(134) - BigInt::from(1),
        ]
    }
}

impl WeierstrassEmulationParams for WeierstrassBls12381 {
    fn a() -> BigInt {
        fe_to_bigint_le(&<midnight_curves::G1Projective as WeierstrassCurve>::A)
    }

    fn b() -> BigInt {
        fe_to_bigint_le(&<midnight_curves::G1Projective as WeierstrassCurve>::B)
    }
}

impl Chip for WeierstrassBls12381 {
    fn advice_columns() -> Vec<Column> {
        <WeierstrassChip as WeierstrassChipTrait<WeierstrassBls12381>>::advice()
    }

    fn extra_columns() -> Vec<Column> {
        <WeierstrassChip as WeierstrassChipTrait<WeierstrassBls12381>>::extra_fixed()
    }

    fn gate_args() -> Vec<Argument> {
        <WeierstrassChip as WeierstrassChipTrait<WeierstrassBls12381>>::gates()
    }

    fn lookup_args() -> Vec<Argument> {
        <WeierstrassChip as WeierstrassChipTrait<WeierstrassBls12381>>::lookups()
    }

    fn lookup_tables() -> Vec<LookupTable> {
        <WeierstrassChip as WeierstrassChipTrait<WeierstrassBls12381>>::lookup_tables()
    }

    fn chip_deps() -> Vec<SupportedChips> {
        vec![SupportedChips::Native]
    }
}
