use aiken/collection/list.{foldl, zip}
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/scalar.{Scalar, add, from_int, to_int, mul, field_prime}

pub fn inner_product(
  a: List<State<Scalar>>,
  b: List<State<Scalar>>,
) -> State<Scalar> {
  foldl(zip(a, b), from_int(0), fn((a, b), acc) { add(mul(a, b), acc) })
}

/// Fast modular multiplicative inverse using Extended Euclidean Algorithm
/// This is ~3-4x faster than the Fermat-based approach implemented in the Aiken stdlib
pub fn recip_eea(self: State<Scalar>) -> State<Scalar> {
  let a = to_int(self)
  let inv = egcd_go(a, field_prime, 1, 0)
  from_int(inv)
}

/// Extended Euclidean Algorithm for modular inverse
/// Computes x such that (a * x) mod m = 1
/// Invariant: a*x1 + m*x2 = u (mod m)
fn egcd_go(u: Int, v: Int, x1: Int, x2: Int) -> Int {
  if u == 1 {
    // Found inverse, ensure it's positive
    x1 % field_prime 
  } else {
    let q = v / u
    let r = v % u
    let x = x2 - q * x1
    egcd_go(r, u, x, x1)
  }
}

// Test that it produces correct results
test test_recip_eea() {
  let x = from_int(834884848)
  let expected = from_int(
    35891248691642227249400403463796410930702563777316955162085759263735363466421
  )

  recip_eea(x) == expected
}