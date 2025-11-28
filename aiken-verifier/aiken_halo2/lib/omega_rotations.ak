use aiken/collection/list.{map, range}
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/scalar.{Scalar, from_int, mul, scale}
use aiken/math.{abs}

pub fn rotate_omegas(
  omega: State<Scalar>,
  omega_inv: State<Scalar>,
  from: Int,
  to: Int,
) -> List<State<Scalar>> {
  map(
    range(from, to),
    fn(value) { rotate_omega(omega, omega_inv, from_int(1), value) },
  )
}

pub fn rotate_omega(
  omega: State<Scalar>,
  omega_inv: State<Scalar>,
  value: State<Scalar>,
  rotation: Int,
) -> State<Scalar> {
  if rotation < 0 {
    mul(scale(omega_inv, abs(rotation)), value)
  } else {
    mul(scale(omega, rotation), value)
  }
}

fn go(
  first: State<Scalar>,
  num: Int,
  base: State<Scalar>,
) -> List<State<Scalar>> {
  if num == 0 {
    []
  } else {
    [first, ..go(mul(base, first), num - 1, base)]
  }
}

pub fn powers(num: Int, base: State<Scalar>) -> List<State<Scalar>> {
  go(from_int(1), num, base)
}

// values based on atms circuit results
test calculate_rotations() {
  let omega: State<Scalar> =
    from_int(0x56624634b500a166dc86b01c0d477fa6ae4622f6a9152435034d2ff22a5ad9e1)
  let omega_inv: State<Scalar> =
    from_int(0x281f74790b85a216fd013df1f683bf99a14c38253fdb838cd7a1f5bc8f529599)

  let from = -6
  let to = 0

  let result = rotate_omegas(omega, omega_inv, from, to)

  expect
    [
      from_int(
        0xb86cb0cc9981913c405642e1a61b6c2ebb2c035b286d62963161b0e604f2b5c,
      ),
      from_int(
        0x2d81596dda5e65d78aa2fbc9a41187afb2125a3ed8061f1633d09f0c1577c836,
      ),
      from_int(
        0x391b2856c609b4784ae25ffab9dc59865046d17864183203961a252dd8543362,
      ),
      from_int(
        0x1cd54bc8adcd5dab7989ec74ae3f47f4588f2deee2a0d9a40404e47eecd35df7,
      ),
      from_int(
        0x57e6990d4981b177d548fda262008419204f9476cecef2df68946aad325251ed,
      ),
      from_int(
        0x281f74790b85a216fd013df1f683bf99a14c38253fdb838cd7a1f5bc8f529599,
      ),
      from_int(1),
    ] == result
}
