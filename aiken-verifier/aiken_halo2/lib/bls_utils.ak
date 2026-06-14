use aiken/collection/list.{all, concat, foldl, map, push, range, zip}
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/g1.{
  add as add_g1, compress, decompress, equal, generator, scale, zero,
}
use aiken/crypto/bls12_381/scalar.{
  Scalar, add, field_prime, from_int, mul, recip, to_int,
}
use aiken/fuzz
use aiken/option.{is_some}
use aiken/primitive/bytearray

// BLS12-381 base field prime (Fp)
const fp_prime: Int =
  0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

// In a 48-byte compressed BLS12-381 G1 encoding, the top 3 bits of the first byte are flags:
//   bit 7 (0x80) -- compression flag (point is compressed)
//   bit 6 (0x40) -- infinity flag
//   bit 5 (0x20) -- parity flag (y is the lexicographically larger root)

// compression flag only -- 0x80 in the high byte (= 0x80 << 376)
const compression_flag: Int =
  19701003098197239606139520050071806902539869635232723333974146702122860885748605305707133127442457820403313995153408

// compression flag + parity flag -- 0xa0 in the high byte (= 0xa0 << 376)
const compression_and_parity_flag: Int =
  24626253872746549507674400062589758628174837044040904167467683377653576107185756632133916409303072275504142493941760

// Function returning a G1 element from two scalar coordinates
// We assume the point is not at infinity
pub fn g1_from_coords(x: Int, y: Int) -> G1Element {
  // 1. Build the flags
  // The compression flag (first bit) is set to 1
  // The parity flag (third bit) is set to 1 if y is the lexicographically largest
  let other_y = fp_prime - y
  let flags =
    if y > other_y {
      compression_and_parity_flag
    } else {
      compression_flag
    }

  // 2. Add flags to x coordinate
  let compressed_point = bytearray.from_int_big_endian(x + flags, 48)

  // 3. Decompress to get the G1 element
  decompress(compressed_point)
}

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

test coord_generator() {
  let x =
    0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
  let y =
    0x8b3f481e3aaa0f1a09d8a7e0e1f7b6b8f3d3d5a7b7a2c6b6d2f5e8c3b9a1d0e4c8f6a1b2c3d4e5f60718293a4b5c6d7

  let p = g1_from_coords(x, y)

  expect equal(p, generator)
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
