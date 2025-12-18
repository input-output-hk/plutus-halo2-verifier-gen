use aiken/crypto/bls12_381/scalar.{from_int}
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use proof_verifier.{verifier}

type Redeemer =
  (ByteArray, Int, Int, Int)

validator halo2 {
  mint(redeemer: Redeemer, _policy_id: PolicyId, _self: Transaction) {
    let (proof, instance_1, instance_2, instance_3) = redeemer

    verifier(
      proof,
      from_int(
        0x2a96baae6fe129a071c67837627eec433e25e309f3ed0770f923002e7d0d35d1,
      ),
      from_int(instance_1),
      from_int(instance_2),
      from_int(instance_3),
    )
  }

  else(_) {
    fail
  }
}
