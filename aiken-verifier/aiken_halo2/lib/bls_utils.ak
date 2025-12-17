use aiken/collection/list.{all, concat, foldl, map, push, range, zip}
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/g1.{add as add_g1, decompress, scale, zero}
use aiken/crypto/bls12_381/scalar.{
  Scalar, add, field_prime, from_int, mul, recip, to_int,
}
use aiken/fuzz
use aiken/option.{is_some}

pub type MSMElement {
  scalar: State<Scalar>,
  g1: ByteArray,
}

pub type MSM {
  elements: List<MSMElement>,
}

pub fn append_term(msm: MSM, element: MSMElement) -> MSM {
  MSM { elements: push(msm.elements, element) }
}

pub fn add_msm(a: MSM, b: MSM) -> MSM {
  MSM { elements: concat(a.elements, b.elements) }
}

pub fn scale_msm(s: State<Scalar>, msm: MSM) -> MSM {
  MSM {
    elements: map(
      msm.elements,
      fn(e) { MSMElement { g1: e.g1, scalar: mul(s, e.scalar) } },
    ),
  }
}

pub fn eval(msm: MSM) -> G1Element {
  foldl(
    msm.elements,
    zero,
    fn(element, acc) {
      let g1 = decompress(element.g1)
      add_g1(acc, scale(g1, element.scalar))
    },
  )
}

pub fn inner_product(
  a: List<State<Scalar>>,
  b: List<State<Scalar>>,
) -> State<Scalar> {
  foldl(zip(a, b), from_int(0), fn((a, b), acc) { add(mul(a, b), acc) })
}

// TODO: Replace with built-in primitive, once `expModInteger` available in Plutus
/// Fast modular multiplicative inverse using Extended Euclidean Algorithm
/// This is orders of magnitude cheaper than the Fermat-based approach implemented in the Aiken stdlib
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
  let x =
    if n != 0 {
      from_int(n)
    } else {
      from_int(1)
    }
  // zero would panic
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
  recip_eea(zero) == zero
}

test recip_eea_benchmark() {
  range(1, 100) |> all(fn(n) { recip_eea(from_int(n)) != from_int(0) })
}

test recip_stdlib_benchmark() {
  range(1, 100) |> all(fn(n) { is_some(recip(from_int(n))) })
}
