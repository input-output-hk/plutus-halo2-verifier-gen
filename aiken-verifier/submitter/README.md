# Aiken Verifier Submitter

On-chain testing tool for submitting Halo2 proof verification transactions to Cardano PreProd testnet. The submitter
creates an on-chain transaction that executes the Aiken Halo2 verifier with the generated proof. If the proof validation
succeeds, the transaction **mints an NFT** as proof of successful verification.

## Setup

### 1. Generate Cardano Address

Generate a private key and address:

```bash
cd aiken-verifier/submitter
cargo run --bin generate_private_key
```

This outputs a private key and corresponding Cardano address.

### 2. Fund Your Address

Send tADA to the generated address using the [PreProd Faucet](https://docs.cardano.org/cardano-testnets/tools/faucet/).

### 3. Get Blockfrost API Key

Get your Blockfrost API key from [blockfrost.io](https://blockfrost.io) (select PreProd network).

### 4. Configure Environment

Create `.env` file in the `aiken-verifier` directory with your private key and Blockfrost API key:

```bash
PRIVATE_KEY=your_private_key_here
BLOCK_FROST_API_KEY=your_blockfrost_api_key_here
```

## Usage

### 1. Generate Verifier and Proof

From the repository root, generate the Aiken verifier code and proof data:

```bash
cargo run --example atms
```

This creates:

- `aiken-verifier/aiken_halo2/lib/proof_verifier.ak` - Verifier code
- `aiken-verifier/submitter/serialized_proof.json` - Proof data
- `aiken-verifier/submitter/serialized_public_inputs.hex` - Public inputs

### 2. Build Aiken Validator

Compile the Aiken project:

```bash
cd aiken-verifier/aiken_halo2
aiken build
```

This generates `plutus.json` with the compiled UPLC validator.

### 3. Submit Transaction

Submit the proof verification transaction to PreProd:

```bash
cd aiken-verifier/submitter
cargo run --bin submitter
```

The submitter:

1. Loads the compiled UPLC validator and proof data
2. Constructs a transaction using Cardano serialization library
3. Submits to PreProd via Blockfrost API
4. Waits for on-chain confirmation

### 4. Verify Transaction

Check the transaction hash in the logs using a PreProd explorer:

- [CardanoScan PreProd](https://preprod.cardanoscan.io)
- [Cexplorer PreProd](https://preprod.cexplorer.io)

