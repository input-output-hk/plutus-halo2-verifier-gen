use num_bigint::{BigInt, BigUint, Sign, ToBigInt};
use num_traits::{Num, One, Signed, Zero};
use std::ops::Rem;

use ff::PrimeField;

/// Sum the given `coeffs` pair-wise multiplied by the given `values`.
pub fn sum_bigints(coeffs: &[BigInt], values: &[BigInt]) -> BigInt {
    debug_assert!(coeffs.len() == values.len());
    values
        .iter()
        .zip(coeffs.iter())
        .map(|(v, b)| b * v)
        .sum::<BigInt>()
}

/// Computes the logarithm in base 2 of the given value, rounded up.
pub fn ceil_log2(value: &BigInt) -> u32 {
    BigInt::bits(&(value - BigInt::one())) as u32
}

/// Computes the smallest n such that 2^n is >= the given value.
pub fn next_power_of_two(value: &BigInt) -> BigInt {
    BigInt::pow(&BigInt::from(2), ceil_log2(value))
}

/// Like .rem, but gives positive answers only.
pub fn urem(value: &BigInt, modulus: &BigInt) -> BigInt {
    let mut output = value.rem(modulus);
    if output.is_negative() {
        output += modulus;
    }
    output
}

pub fn non_zero(value: &BigInt) -> usize {
    !value.is_zero() as usize
}

pub fn non_trivial(value: &BigInt) -> usize {
    (!value.is_zero() && !value.is_one()) as usize
}

pub fn to_bigint(modulo: &'static str) -> BigInt {
    // Removing the "0x" before converting
    BigUint::from_str_radix(&modulo[2..], 16)
        .unwrap()
        .to_bigint()
        .unwrap()
}

pub fn fe_to_bigint<F: PrimeField>(value: &F) -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, F::to_repr(value).as_ref())
}
