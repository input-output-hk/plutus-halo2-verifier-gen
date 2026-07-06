use super::field::{FieldChip, FieldChipTrait};
use crate::plutus_gen::stats::chips::curve::{fe_to_bigint_be, to_bigint};

use super::super::super::{Argument, Chip, Column, LookupTable, SupportedChips};
use super::{
    FieldEmulationParams, WeierstrassChip, WeierstrassChipTrait, WeierstrassEmulationParams,
};

use ff::PrimeField;
use midnight_curves::p256;
use num_bigint::BigInt;
use num_traits::One;

/// Merged Weierstrass ECC, Base & Scalar Field chips for Secp256r1 (foreign field, multi-limb via MEP).
struct WeierstrassSecp256r1Scalar;
pub(crate) struct WeierstrassSecp256r1;

impl FieldEmulationParams for WeierstrassSecp256r1Scalar {
    const LOG2_BASE: u32 = 64;
    const NB_LIMBS: usize = 4;
    const RC_LIMB_SIZE: usize = 17;

    fn modulus() -> BigInt {
        to_bigint(p256::Fq::MODULUS)
    }

    fn moduli() -> Vec<BigInt> {
        vec![
            BigInt::from(2).pow(118),
            BigInt::from(2).pow(118) - BigInt::one(),
        ]
    }
}

impl FieldEmulationParams for WeierstrassSecp256r1 {
    const LOG2_BASE: u32 = 64;
    const NB_LIMBS: usize = 4;
    const RC_LIMB_SIZE: usize = 17;

    fn modulus() -> BigInt {
        to_bigint(p256::Fp::MODULUS)
    }

    fn moduli() -> Vec<BigInt> {
        vec![
            BigInt::from(2).pow(122),
            BigInt::from(2).pow(122) - BigInt::from(507376),
        ]
    }
}

impl WeierstrassEmulationParams for WeierstrassSecp256r1 {
    fn a() -> BigInt {
        fe_to_bigint_be(&p256::CURVE_A)
    }
    fn b() -> BigInt {
        fe_to_bigint_be(&p256::CURVE_B)
    }
}

impl Chip for WeierstrassSecp256r1 {
    fn advice_columns() -> Vec<Column> {
        let scalar_advices = <FieldChip as FieldChipTrait<WeierstrassSecp256r1Scalar>>::advice();
        let ecc_advices = <WeierstrassChip as WeierstrassChipTrait<WeierstrassSecp256r1>>::advice();

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

    fn extra_columns() -> Vec<Column> {
        let scalar_fixed = <FieldChip as FieldChipTrait<WeierstrassSecp256r1Scalar>>::extra_fixed();
        let ecc_fixed =
            <WeierstrassChip as WeierstrassChipTrait<WeierstrassSecp256r1>>::extra_fixed();

        [scalar_fixed, ecc_fixed].concat()
    }

    fn gate_args() -> Vec<Argument> {
        let scalar_args = <FieldChip as FieldChipTrait<WeierstrassSecp256r1Scalar>>::gates();

        let ecc_args = <WeierstrassChip as WeierstrassChipTrait<WeierstrassSecp256r1>>::gates();

        [scalar_args, ecc_args].concat()
    }

    fn lookup_args() -> Vec<Argument> {
        <WeierstrassChip as WeierstrassChipTrait<WeierstrassSecp256r1>>::lookups()
    }

    fn lookup_tables() -> Vec<LookupTable> {
        <WeierstrassChip as WeierstrassChipTrait<WeierstrassSecp256r1>>::lookup_tables()
    }

    fn chip_deps() -> Vec<SupportedChips> {
        vec![SupportedChips::Native]
    }
}
