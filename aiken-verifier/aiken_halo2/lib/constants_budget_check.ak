use aiken/crypto/bls12_381/g1.{generator as generatorG1}
use aiken/crypto/bls12_381/g2.{generator as generatorG2}
use verifier_key.{
  f0_commitment, f10_commitment, f11_commitment, f12_commitment, f13_commitment,
  f14_commitment, f15_commitment, f16_commitment, f17_commitment, f18_commitment,
  f19_commitment, f1_commitment, f2_commitment, f3_commitment, f4_commitment,
  f5_commitment, f6_commitment, f7_commitment, f8_commitment, f9_commitment,
  g2_const, p0_commitment, p1_commitment, p2_commitment, p3_commitment,
  p4_commitment, p5_commitment, p6_commitment, p7_commitment, p8_commitment,
}

// this test is for checking how much budget is used when G1 constants are used in script, assertions are only to force use of the constant
// this test depends on data generated with cargo run --example atms_with_lookups
// you have to run that command before running this tes
test use_constants() {
  expect p0_commitment != generatorG1
  expect p1_commitment != generatorG1
  expect p2_commitment != generatorG1
  expect p3_commitment != generatorG1
  expect p4_commitment != generatorG1
  expect p5_commitment != generatorG1
  expect p6_commitment != generatorG1
  expect p7_commitment != generatorG1
  expect p8_commitment != generatorG1

  expect f0_commitment != generatorG1
  expect f1_commitment != generatorG1
  expect f2_commitment != generatorG1
  expect f3_commitment != generatorG1
  expect f4_commitment != generatorG1
  expect f5_commitment != generatorG1
  expect f6_commitment != generatorG1
  expect f7_commitment != generatorG1
  expect f8_commitment != generatorG1
  expect f9_commitment != generatorG1
  expect f10_commitment != generatorG1
  expect f11_commitment != generatorG1
  expect f12_commitment != generatorG1
  expect f13_commitment != generatorG1
  expect f14_commitment != generatorG1
  expect f15_commitment != generatorG1
  expect f16_commitment != generatorG1
  expect f17_commitment != generatorG1
  expect f18_commitment != generatorG1
  expect f19_commitment != generatorG1

  expect g2_const != generatorG2
}
