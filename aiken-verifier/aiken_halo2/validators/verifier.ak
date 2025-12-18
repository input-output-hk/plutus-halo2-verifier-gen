use aiken/crypto/bls12_381/scalar.{from_int}
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use proof_verifier.{verifier}
use verifier_key.{transcript_rep}

type Redeemer =
  (ByteArray, Int, Int, Int)

validator halo2 {
  mint(redeemer: Redeemer, _policy_id: PolicyId, _self: Transaction) {
    let (proof, instance_1, instance_2, instance_3) = redeemer

    verifier(
      proof,
      transcript_rep,
      from_int(instance_1),
      from_int(instance_2),
      from_int(instance_3),
    )
  }

  else(_) {
    fail
  }
}
