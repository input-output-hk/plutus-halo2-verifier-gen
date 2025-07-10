# Plutus Halo2 Verifier

A Rust tool that generates Plutus verifiers for Halo2 circuits, enabling verification of proofs on the Cardano
blockchain.

> ### ⚠️ Security Disclaimer
>
> **This repository contains proof-of-concept implementations** intended to evaluate the feasibility of verifying Halo2
> proofs in Plutus smart contracts. The code has not been thoroughly tested and audited and is not intended for
> production use. It is provided for research and educational purposes only.

## Overview

This project bridges Rust-based Halo2 implementations with Plutus smart contracts on Cardano. It
extracts verification keys and circuit structures from Halo2 circuits and generates corresponding Plinth verifier code
that can validate proofs on-chain.

## Features

- **Circuit-Agnostic Generation**: Automatically generates Plinth verifiers for various Halo2 circuits
- **Template-Based Code Generation**: Uses Handlebars templates for flexible verifier generation
- **Multiple Circuit Types**: Supports basic Halo2 circuits, lookup tables, and custom gates

## Architecture

### Core Components

1. **Halo2 proof generation in Rust** (`src/`)
    - Circuit definitions and implementations
    - Proof generation and verification

2. **Plutus Generation Pipeline** (`src/plutus_gen/`)
    - `extraction/`: Extracts circuit data from Halo2 structures
    - `code_emitters.rs`: Generates Plinth code from templates that is optimized to verify a particular circuit

3. **Plutus Verifier** (`plutus-verifier/`)
    - Common Plinth code for Halo2 verification
    - Template files for circuit-tailored code generation

### Workflow

1. Define Halo2 circuit in Rust
2. Generate proving/verifying keys
3. Extract circuit structure and constraints
4. Generate Plinth verifier code using templates
5. Deploy verifier to Cardano for on-chain verification

## Build prerequisites

The prototype consists of two main parts:

1. The Rust component generates a Halo2 proof and produces the corresponding Plinth verifier code.
    - it can be build using the standard `cargo` tooling from the root of the repository.
2. The Plinth component contains template files and serves as the target location for inserting the generated Plinth
   verifier.
    - Plinth smart contract can be build using `cabal` in `nix` environment.

#### How to install and use nix

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
cd plutus-verifier
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

## Running Examples

### Rust part

The repository includes several example circuits:

* `simple_mul` - Simple multiplication circuit with standard PLONK gates
* `atms` - Advanced ATMS (Aggregate Threshold Multisignature) circuit for aggregating signatures with threshold
  validation. Based on [input-output-hk/sidechains-zk](https://github.com/input-output-hk/sidechains-zk)
* `atms_with_lookups` - A circuit that verifies ATMS signature and lookup argument
* `lookup_table` - A circuit with lookup argument

```bash
# Simple multiplication circuit
cargo run --example simple_mul

# ATMS (Aggregate Threshold Multisignature) circuit 
cargo run --example atms

# ATMS with lookup tables
cargo run --example atms_with_lookups

# Lookup table circuit
cargo run --example lookup_table

# With detailed logging
RUST_LOG=debug cargo run --example simple_mul

# With Plutus traces (note that Plutus traces will increase contract cost!)
RUST_LOG=debug cargo run --example simple_mul --feature plutus_debug
```

Running an example will generate the verification and proving keys for the circuit, create a proof using test public
inputs, and produce the corresponding Plinth verifier code. The generated files will be saved in their respective
locations within the plutus-verifier folder:

* The generated proof is saved in `./plutus-verifier/plutus-halo2/test/Generic/serialized_proof.json`.
* The public inputs are saved in `./templates/generic/plutus-halo2/test/Generic/serialized_public_inputs.hex`.
* The generated Plinth code is saved in:

```
./plutus-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/generic/Verifier.hs
./plutus-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/generic/VKConstants.hs
```

### Plutus part

After the Rust part is executed you can test Plutus verifier as follows:
```bash
nix develop github:input-output-hk/devx#ghc96-iog
cd plutus-verifier
cabal build -j all
cabal test all
```

## Benchmarks

Below are the execution costs of Plutus scripts running the Halo2 verifier for various circuits:

| Circuit description             | Script size<br/>(% of script limit 14kb) | CPU usage               | Mem usage         |
|---------------------------------|------------------------------------------|-------------------------|-------------------|
| **Simple mul**                  | 6498  (45.3%)                            | 5,246,865,172  (52.47%) | 3,750,211 (26.7%) |
| **Lookup table**                | 11981 (83.56%)                           | 8,508,800,375  (85.09%) | 4,506,048 (32.1%) |
| **ATMS (50 out of 90)**         | 12542 (87.5%)                            | 9,049,726,110  (90.5%)  | 4,531,396 (32.3%) |
| **ATMS (228 out of 408)**       | 12542 (87.5%)                            | 9,037,616,234  (90.3%)  | 4,488,266 (32.0%) |
| **ATMS (50/90) + lookup table** | 15246 (106.3%)                           | 10,733,382,733 (107.3%) | 4,882,403 (34.8%) |

## License

Copyright 2025 Input Output Global

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this repository except in compliance
with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "
AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License