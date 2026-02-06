# Plutus Halo2 Verifier

A Rust tool that generates Plutus verifiers for Halo2 circuits in both **Plinth** and **Aiken** smart contract
languages, enabling verification of proofs on the Cardano blockchain.

> ### ⚠️ Important Disclaimer & Acceptance of Risk
>
> **This repository contains proof-of-concept implementations** intended to evaluate the feasibility of verifying Halo2
> proofs in Plutus smart contracts. This code is provided "as is" for research and educational purposes only. It has not
> been thoroughly tested and audited and is not intended for production use. By using this code, you acknowledge and
> accept all associated risks, and our company disclaims any liability for damages or losses.

## Overview

This project bridges Rust-based Halo2 implementations with Plutus smart contracts on Cardano. It
extracts verification keys and circuit structures from Halo2 circuits and generates corresponding verifier code
in either **Plinth** (Haskell-based) or **Aiken** (Rust-like functional smart contract language) that can validate
proofs on-chain.

## Architecture

### Core Components

1. **Halo2 proof generation in Rust** (`src/`)
    - Circuit definitions and implementations
    - Proof generation and verification

2. **Plutus Generation Pipeline** (`src/plutus_gen/`)
    - `extraction/`: Extracts circuit data from Halo2 structures
    - `code_emitters_plinth.rs`: Generates Plinth code from Handlebars templates optimized for specific circuits
    - `code_emitters_aiken.rs`: Generates Aiken code from Handlebars templates optimized for specific circuits

3. **Plinth Verifier** (`plinth-verifier/`)
    - Common Plinth code for Halo2 verification
    - Handlebars template files for circuit-tailored code generation

4. **Aiken Verifier** (`aiken-verifier/`)
    - Common Aiken code for Halo2 verification (BLS12-381 operations, MSM, KZG commitments)
    - Handlebars template files for circuit-tailored code generation
    - Submitter for on-chain testing

### Workflow

1. Define Halo2 circuit in Rust
2. Generate proving/verifying keys
3. Extract circuit structure and constraints
4. Generate optimized verifier code in target language (either Plinth or Aiken)
5. Integrate verifier into smart contract to be deployed on Cardano

## Build prerequisites

The prototype consists of three main parts:

1. **Rust component**: Generates Halo2 proofs and produces verifier code for either Plinth or Aiken
    - Built using standard `cargo` tooling from the root of the repository

2. **Plinth component** (`plinth-verifier/`): Haskell-based smart contract verifier
    - Built using `cabal` in `nix` environment

3. **Aiken component** (`aiken-verifier/aiken_halo2/`): Aiken smart contract verifier
    - Built using `aiken` toolchain

#### How to install and use nix (necessary only for Plinth part)

1. Install `nix` - the package manager

```
sh <(curl -L https://nixos.org/nix/install)
```

2. Modify the conf file `/etc/nix/nix.conf` by adding

```
substituters = https://cache.nixos.org https://cache.iog.io
trusted-public-keys = hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ= cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
experimental-features = nix-command flakes
allow-import-from-derivation = "true"
```

3. The contract can be build from the relevant templates folder using the nix shell:

```bash
nix develop github:input-output-hk/devx#ghc96-iog
cd plinth-verifier
cabal build -j all
cabal test all
```

If you have build errors due to missing package descriptions like this:

```bash
.....
Error: cabal: No cabal file found.
Please create a package description file <pkgname>.cabal
Failed to build random-shuffle-0.0.4. The failure occurred during the
configure step.
.....
```

just try to re-run the build (may require several re-runs).

#### How to install and use Aiken

1. Install `aiken` - the Aiken smart contract language toolchain

Follow the installation instructions at https://aiken-lang.org/installation-instructions

2. The Aiken verifier can be built from the aiken-verifier directory:

```bash
cd aiken-verifier/aiken_halo2
aiken check
aiken build
```

## Running Examples

### Rust part (generating verifiers)

The repository includes several example circuits:

* `simple_mul` - Simple multiplication circuit with standard PLONK gates
* `atms` - Advanced ATMS (Aggregate Threshold Multisignature) circuit for aggregating signatures with threshold
  validation. Based on [input-output-hk/sidechains-zk](https://github.com/input-output-hk/sidechains-zk)
* `atms_with_lookups` - A circuit that verifies ATMS signature and lookup argument
* `lookup_table` - A circuit with lookup argument

```bash
# Simple multiplication circuit (Halo2 KZG)
cargo run --example simple_mul

# ATMS (Aggregate Threshold Multisignature) circuit Halo2 KZG
cargo run --example atms

# ATMS with dummy lookup tables (Halo2 KZG)
cargo run --example atms_with_lookups

# Lookup table circuit (Halo2 KZG)
cargo run --example lookup_table

# With detailed logging
RUST_LOG=debug cargo run --example simple_mul

# With Plutus traces (note that Plutus traces will increase contract cost!)
RUST_LOG=debug cargo run --example simple_mul --features plutus_debug
```

Running an example will generate the verification and proving keys for the circuit, create a proof using test public
inputs, and produce verifier code for **both Plinth and Aiken**. The generated files will be saved in their respective
locations:

**Plinth verifier:**

* The generated proof is saved in `./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.json`.
* The public inputs are saved in `./plinth-verifier/plutus-halo2/test/Generic/serialized_public_inputs.hex`.
* The generated Plinth verifier code is saved in:

```
./plinth-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/Verifier.hs
./plinth-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/VKConstants.hs
```

**Aiken verifier:**

* The generated proof is saved in `./aiken-verifier/submitter/serialized_proof.json`.
* The public inputs are saved in `./aiken-verifier/submitter/serialized_public_inputs.hex`.
* The generated Aiken verifier code is saved in:

```
./aiken-verifier/aiken_halo2/lib/proof_verifier.ak
./aiken-verifier/aiken_halo2/lib/vk.ak
```

### Plinth part (running generated Plinth verifier)

After the Rust part is executed you can test the Plinth verifier as follows:

```bash
nix develop github:input-output-hk/devx#ghc96-iog
cd plinth-verifier
cabal build -j all
cabal test all
```

### Aiken part (running generated Aiken verifier)

After the Rust part is executed you can test the Aiken verifier as follows:

```bash
cd aiken-verifier/aiken_halo2
aiken check
aiken build
```

## Benchmarks

Below are the execution costs of both Plinth and Aiken scripts running the Halo2 verifier for various circuits:

| Circuit description             | Script size*</br>Plinth | Script size*</br>Aiken | CPU usage</br>Plinth | CPU usage</br>Aiken | Mem usage</br>Plinth | Mem usage</br>Aiken | 
|---------------------------------|-------------------------|------------------------|----------------------|---------------------|----------------------|---------------------|
| **Simple mul**                  |                         |                        |                      |                     |                      |                     |
| **Lookup table**                |                         |                        |                      |                     |                      |                     |
| **ATMS (50 out of 90)**         |                         |                        |                      |                     |                      |                     |
| **ATMS (228 out of 408)**       |                         |                        |                      |                     |                      |                     |
| **ATMS (50/90) + lookup table** |                         |                        |                      |                     |                      |                     |

\* Script size % is taken as a percentage of the 16kb script limit

**Note that the benchmark numbers are approximate.** Even for the same circuit, the verifier's execution cost may vary
slightly depending on the specific proof being verified. This variation stems from the randomness used during proof
generation, which can be influenced by the initial seed or the platform on which the prover runs.

### Further improvements

The upcoming CIP-109 (built-in modular inversion) and CIP-133 (built-in multi-scalar multiplication) are expected to
significantly reduce the on-chain costs of the verifiers.

## License

Copyright 2025 Input Output Global

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this repository except in compliance
with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "
AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License
