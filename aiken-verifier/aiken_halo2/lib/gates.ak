use aiken/crypto/bls12_381/scalar.{
  Scalar, add, field_prime as bls12_381_field_prime, from_int, mul, neg, to_int,
}

// this test is only to make sure all imports are there
test check_imports() {
  let a = from_int(42)
  let b = from_int(24)

  add(mul(from_int(36), add(a, b)), neg(b)) == from_int(2352)
}
