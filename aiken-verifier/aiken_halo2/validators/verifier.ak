use aiken/builtin.{append_bytearray}
use aiken/crypto.{blake2b_256}
use aiken/crypto/bls12_381/scalar.{from_bytes, from_int}
use aiken/primitive/bytearray.{from_int_big_endian}
use cardano/assets.{PolicyId, has_nft_strict}
use cardano/transaction.{Transaction}
use proof_verifier.{verifier}

type Redeemer =
  (ByteArray, ByteArray, ByteArray, ByteArray)

validator halo2 {
  mint(redeemer: Redeemer, policy_id: PolicyId, transaction: Transaction) {
    let (proof, instance_1, instance_2, instance_3) = redeemer

    let for_hashing =
      append_bytearray(
        append_bytearray(append_bytearray(proof, instance_1), instance_2),
        instance_3,
      )

    let expected_nft_name = blake2b_256(for_hashing)

    expect has_nft_strict(transaction.mint, policy_id, expected_nft_name)

    verifier(
      proof,
      from_bytes(instance_1),
      from_bytes(instance_2),
      from_bytes(instance_3),
    )
  }

  else(_) {
    fail
  }
}
