use aiken/builtin.{append_bytearray}
use aiken/crypto.{blake2b_256}
use aiken/crypto/bls12_381/scalar.{from_int}
use aiken/primitive/bytearray.{from_int_big_endian}
use cardano/assets.{PolicyId, has_nft_strict}
use cardano/transaction.{Transaction}
use proof_verifier.{verifier}

type Redeemer =
  (ByteArray, Int, Int, Int)

validator halo2 {
  mint(redeemer: Redeemer, policy_id: PolicyId, transaction: Transaction) {
    let (proof, instance_1, instance_2, instance_3) = redeemer

    let for_hashing =
      append_bytearray(
        append_bytearray(
          append_bytearray(proof, from_int_big_endian(instance_1, 32)),
          from_int_big_endian(instance_2, 32),
        ),
        from_int_big_endian(instance_3, 32),
      )

    let expected_nft_name = blake2b_256(for_hashing)

    expect has_nft_strict(transaction.mint, policy_id, expected_nft_name)

    verifier(
      proof,
      from_int(instance_1),
      from_int(instance_2),
      from_int(instance_3),
    )
  }

  else(_) {
    fail
  }
}
