use aiken/collection/list.{all, foldl, range, zip}
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/scalar.{Scalar, add, from_int, to_int, mul, recip, field_prime}
use aiken/fuzz
use aiken/option.{is_some}

pub fn inner_product(
  a: List<State<Scalar>>,
  b: List<State<Scalar>>,
) -> State<Scalar> {
  foldl(zip(a, b), from_int(0), fn((a, b), acc) { add(mul(a, b), acc) })
}

/// Fast modular multiplicative inverse using Extended Euclidean Algorithm
/// This is orders of magnitude cheaper than the Fermat-based approach implemented in the Aiken stdlib
// TODO: Replace with built-in primitive, once `expModInteger` available in Plutus
pub fn recip_eea(x: State<Scalar>) -> State<Scalar> {
  let a = to_int(x)
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

test recip_eea_prop(n via fuzz.int()) {
  let x = if n != 0 { from_int(n) } else { from_int(1) } // zero would panic
  let x_inv = recip_eea(x)
  
  expect mul(x, x_inv) == from_int(1)

  expect Some(stdlib_inv) = recip(x)
  expect x_inv == stdlib_inv
}

test recip_eea_edge_cases() {
  expect recip_eea(from_int(1)) == from_int(1)
  
  let minus_one = from_int(field_prime - 1)
  expect recip_eea(minus_one) == minus_one
}

test recip_eea_panics_on_zero() fail {
  let zero = from_int(0)
  recip_eea(zero) == zero  // should panic because 0 has no multiplicative inverse
}

test recip_eea_benchmark() {
  range(1, 100) |> all(fn(n) { recip_eea(from_int(n)) != from_int(0) })
}

test recip_stdlib_benchmark() {
  range(1, 100) |> all(fn(n) { is_some(recip(from_int(n))) })
}