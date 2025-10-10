use cardano/assets.{PolicyId}
use cardano/transaction.{ Transaction}

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
  magic_number == 42
}

test mint_with_magic_number() {
  verifier(42)
}
