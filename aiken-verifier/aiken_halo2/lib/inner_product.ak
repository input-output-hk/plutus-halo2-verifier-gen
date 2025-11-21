use aiken/collection/list.{foldl, zip}
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/scalar.{
  Scalar, add, field_prime, from_int, mul, mul_int, recip, scale, sub, sub_int,
}

pub fn inner_product(
  a: List<State<Scalar>>,
  b: List<State<Scalar>>,
) -> State<Scalar> {
  foldl(zip(a, b), from_int(0), fn((a, b), acc) { add(mul(a, b), acc) })
}
