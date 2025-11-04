use aiken/builtin.{bls12_381_final_verify, bls12_381_miller_loop}
use aiken/crypto/bls12_381/g1.{
  add as addG1, generator as generatorG1, scale as scaleG1, sub as subG1,
}
use aiken/crypto/bls12_381/g2.{
  add as addG2, generator as generatorG2, scale as scaleG2, sub as subG2,
}
use aiken/crypto/bls12_381/scalar.{from_int}
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}

type Redeemer =
  Int

validator halo2 {
  mint(redeemer: Redeemer, _policy_id: PolicyId, _self: Transaction) {
    verifier(redeemer)
  }

  else(_) {
    fail
  }
}

fn verifier(magic_number: Int) -> Bool {
  let scalar = from_int(42)

  let result = scaleG1(generatorG1, scalar)
  let result = scaleG1(result, scalar)
  let result = addG1(result, result)
  let result = subG1(result, generatorG1)

  let resultG2 = scaleG2(generatorG2, scalar)
  let resultG2 = scaleG2(resultG2, scalar)
  let resultG2 = addG2(resultG2, resultG2)
  let resultG2 = subG2(resultG2, generatorG2)

  let ml = bls12_381_miller_loop(result, resultG2)

  magic_number == 42 && result != generatorG1 && resultG2 != generatorG2 && bls12_381_final_verify(
    ml,
    ml,
  ) && bls12_381_final_verify(ml, ml)
}

test mint_with_magic_number() {
  verifier(42)
}
