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

/// Reduces `value` modulo `modulus` using the representative closest to zero,
/// i.e. in the range `(-modulus/2, modulus/2]`. This gives tighter bounds than
/// `urem` when the unsigned representative is close to `modulus` (e.g. a
/// curve's `a` coefficient, which is `-3` for secp256r1).
pub fn signed_mod(value: &BigInt, modulus: &BigInt) -> BigInt {
    let r = urem(value, modulus);
    if &r * 2 > *modulus { r - modulus } else { r }
}

pub fn non_zero(value: &BigInt) -> usize {
    !value.is_zero() as usize
}

pub fn non_trivial(value: &BigInt) -> usize {
    (!value.is_zero() && !value.is_one()) as usize
}

/// Counts how many of `values`, reduced mod `modulus`, are non-zero — i.e.
/// need to be added into the gate expression.
pub fn count_non_zero(values: &[BigInt], modulus: &BigInt) -> usize {
    values.iter().map(|v| non_zero(&v.rem(modulus))).sum()
}

/// Counts how many of `values`, reduced mod `modulus`, are non-trivial (i.e.
/// neither 0 nor 1) — i.e. need an extra multiplication by a constant, rather
/// than a bare add.
pub fn count_non_trivial(values: &[BigInt], modulus: &BigInt) -> usize {
    values.iter().map(|v| non_trivial(&v.rem(modulus))).sum()
}

/// The two modulus-reduced quantities `((k_min * m) mod mj, m mod mj)` that
/// every gate's per-modulus identity needs to account for the `u * m` and
/// `k_min * m` terms of `expr = (u + k_min) * m` reduced mod `mj`.
pub fn k_and_m_residues(k_min: &BigInt, m: &BigInt, mj: &BigInt) -> (BigInt, BigInt) {
    (urem(&(k_min * m), mj), urem(m, mj))
}

pub fn to_bigint(modulo: &'static str) -> BigInt {
    let hex = modulo.strip_prefix("0x").unwrap_or(modulo);
    BigUint::from_str_radix(hex, 16)
        .unwrap()
        .to_bigint()
        .unwrap()
}

/// Converts a field element to a `BigInt`, assuming `to_repr()` gives a
/// little-endian canonical representation (true for bls12_381/curve25519).
pub fn fe_to_bigint_le<F: PrimeField>(value: &F) -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, F::to_repr(value).as_ref())
}

/// Like `fe_to_bigint_le`, but for fields whose `to_repr()` gives a big-endian
/// canonical representation instead (true for k256/p256, which follow the
/// SEC1 byte-order convention rather than the `ff`-crate LE convention).
pub fn fe_to_bigint_be<F: PrimeField>(value: &F) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, F::to_repr(value).as_ref())
}
