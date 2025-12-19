# how to mint NFT connected to proof on preprod

## setup

- get an API key from Blockfrost for pre prod network
- generate private key - address pair, with `aiken-verifier/submitter/src/bin/generate_private_key.rs`
- fund address generated with `generate_private_key.rs`
- create `.env` file in repository root and add there data from previous setup steps
  file should look like this:

```
PRIVATE_KEY=private_key_goes_here
BLOCK_FROST_API_KEY=blockfrost_key_goes_here
```

## generating code

- run `cargo run --example atms` this will generate Aiken code, proof data and public inputs data
- run `aiken build` this will build Aiken project and create `aiken-verifier/aiken_halo2/plutus.json` with UPLC code

## submit transaction

- run `aiken-verifier/submitter/src/main.rs` this will pick all the data from setup stage, combine it with compiled uplc
  and inputs to the verifier. Then it will construct transaction with Cardano serialization lib and send it with
  Blockfrost API. Then it waits for the transaction to be confirmed on chain.
- get the transaction hash from the logs and check it with blockchain explorer for pre prod network
