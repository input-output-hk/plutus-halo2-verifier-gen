use super::field::{FieldChip, FieldChipTrait};
use crate::plutus_gen::stats::chips::curve::{fe_to_bigint_le, to_bigint};

use super::super::super::{Argument, Chip, Column, LookupTable, SupportedChips};
use super::{EdwardsChip, EdwardsChipTrait, EdwardsEmulationParams, FieldEmulationParams};

use ff::PrimeField;
use midnight_curves::curve25519;
use num_bigint::BigInt;

/// Merged Weierstrass ECC, Base & Scalar Field chips for secp256k1 (foreign field, multi-limb via MEP).
struct Curve25519Scalar;
pub(crate) struct Curve25519;

impl FieldEmulationParams for Curve25519Scalar {
    const LOG2_BASE: u32 = 51;
    const NB_LIMBS: usize = 5;
    const RC_LIMB_SIZE: usize = 17;

    fn modulus() -> BigInt {
        to_bigint(curve25519::Scalar::MODULUS)
    }

    fn moduli() -> Vec<BigInt> {
        vec![BigInt::from(2).pow(146)]
    }
}

impl FieldEmulationParams for Curve25519 {
    const LOG2_BASE: u32 = 64;
    const NB_LIMBS: usize = 4;
    const RC_LIMB_SIZE: usize = 16;

    fn modulus() -> BigInt {
        to_bigint(curve25519::Fp::MODULUS)
    }

    fn moduli() -> Vec<BigInt> {
        vec![BigInt::from(2).pow(128)]
    }
}

impl EdwardsEmulationParams for Curve25519 {
    fn a() -> BigInt {
        fe_to_bigint_le(&curve25519::CURVE_A)
    }

    fn d() -> BigInt {
        fe_to_bigint_le(&curve25519::CURVE_D)
    }
}

impl Chip for Curve25519 {
    fn advice_columns() -> Vec<Column> {
        let scalar_advices = <FieldChip as FieldChipTrait<Curve25519Scalar>>::advice();
        let ecc_advices = <EdwardsChip as EdwardsChipTrait<Curve25519>>::advice();

        let max_len = std::cmp::max(scalar_advices.len(), ecc_advices.len());
        let mut columns: Vec<Column> = (0..max_len).map(|_| Column::empty_advice()).collect();

        scalar_advices.into_iter().enumerate().for_each(|(i, s)| {
            columns[i].merge_column(s);
        });

        ecc_advices.into_iter().enumerate().for_each(|(i, e)| {
            columns[i].merge_column(e);
        });

        columns
    }

    fn fixed_columns() -> Vec<Column> {
        <EdwardsChip as EdwardsChipTrait<Curve25519>>::fixed()
    }

    fn extra_columns() -> Vec<Column> {
        let scalar_fixed = <FieldChip as FieldChipTrait<Curve25519Scalar>>::extra_fixed();
        let ecc_fixed = <EdwardsChip as EdwardsChipTrait<Curve25519>>::extra_fixed();

        [scalar_fixed, ecc_fixed].concat()
    }

    fn gate_args() -> Vec<Argument> {
        let scalar_args = <FieldChip as FieldChipTrait<Curve25519Scalar>>::gates();

        let ecc_args = <EdwardsChip as EdwardsChipTrait<Curve25519>>::gates();

        [scalar_args, ecc_args].concat()
    }

    fn lookup_args() -> Vec<Argument> {
        <EdwardsChip as EdwardsChipTrait<Curve25519>>::lookups()
    }

    fn lookup_tables() -> Vec<LookupTable> {
        <EdwardsChip as EdwardsChipTrait<Curve25519>>::lookup_tables()
    }

    fn chip_deps() -> Vec<SupportedChips> {
        vec![SupportedChips::Native]
    }
}
