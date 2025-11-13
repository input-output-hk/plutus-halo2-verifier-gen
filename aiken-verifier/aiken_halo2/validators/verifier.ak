use aiken/crypto/bls12_381/scalar.{from_int}
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use proof_verifier.{verifier}

type Redeemer =
  Int

validator halo2 {
  mint(_redeemer: Redeemer, _policy_id: PolicyId, _self: Transaction) {
    //todo dummy params just to make it compile for now, before all elements are implemented
    let proof = #"00"
    let scalar = from_int(42)
    verifier(proof, scalar, scalar, scalar, scalar)
  }

  else(_) {
    fail
  }
}
