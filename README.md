# Plutus Halo2 Verifier

This repository provides two Rust tools for working with Halo2 proofs on the Cardano blockchain:

- **Verifier Generator** — extracts a Halo2 circuit's structure and generates optimized on-chain verifier code in **Plinth** (Haskell) or **Aiken**
- **Cost Estimator** — predicts verifier execution costs (script size, CPU, memory) from circuit parameters, without running a full circuit

> ### ⚠️ Important Disclaimer & Acceptance of Risk
>
> **This repository contains proof-of-concept implementations** intended to evaluate the feasibility of verifying Halo2
> proofs in Plutus smart contracts. This code is provided "as is" for research and educational purposes only. It has not
> been thoroughly tested and audited and is not intended for production use. By using this code, you acknowledge and
> accept all associated risks, and our company disclaims any liability for damages or losses.

## Architecture

### Core Components

1. **Halo2 proof generation in Rust** (`src/`)
    - Circuit definitions and implementations
    - Proof generation and verification

2. **Plutus Generation Pipeline** (`src/plutus_gen/`)
    - `extraction/`: Extracts circuit data from Halo2 structures
    - `emitters/plinth.rs`: Generates Plinth code from Handlebars templates optimized for specific circuits
    - `emitters/aiken.rs`: Generates Aiken code from Handlebars templates optimized for specific circuits
    - `stats/`: Estimates verifier costs from circuit parameters, without a full circuit run

3. **Plinth Verifier** (`plinth-verifier/`) — used by the Verifier Generator only
    - Common Plinth code for Halo2 verification
    - Handlebars template files for circuit-tailored code generation

4. **Aiken Verifier** (`aiken-verifier/`) — used by the Verifier Generator only
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

The Verifier Generator has three components; the Cost Estimator only requires the Rust component.

1. **Rust component**: Generates Halo2 proofs and produces verifier code for either Plinth or Aiken
    - Built using standard `cargo` tooling from the root of the repository

2. **Plinth component** (`plinth-verifier/`): Haskell-based smart contract verifier — Verifier Generator only
    - Built using `cabal` in `nix` environment

3. **Aiken component** (`aiken-verifier/aiken_halo2/`): Aiken smart contract verifier — Verifier Generator only
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
allow-import-from-derivation = true
```

3. The contract can be build from the relevant templates folder using the nix shell:

```bash
nix develop github:input-output-hk/devx#ghc96-iog
cd plinth-verifier
cabal update
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

## Verifier Generator

The Verifier Generator takes a Halo2 circuit, extracts its verification key and constraint structure, and emits
ready-to-deploy verifier code for either Plinth or Aiken.

### Examples

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
* The public inputs are saved in `./plinth-verifier/plutus-halo2/test/Generic/serialized_public_input.hex`.
* The generated Plinth verifier code is saved in:

```
./plinth-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/Verifier.hs
./plinth-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/VKConstants.hs
```

**Aiken verifier:**

* The generated proof is saved in `./aiken-verifier/submitter/serialized_proof.hex`.
* The public inputs are saved in `./aiken-verifier/submitter/serialized_public_input.hex`.
* The generated Aiken verifier code is saved in:

```
./aiken-verifier/aiken_halo2/lib/proof_verifier.ak
./aiken-verifier/aiken_halo2/lib/verifier_key.ak
```

### Running the generated Plinth verifier

After the Rust part is executed you can test the Plinth verifier as follows:

```bash
nix develop github:input-output-hk/devx#ghc96-iog
cd plinth-verifier
cabal build -j all
cabal test all
```

### Running the generated Aiken verifier

After the Rust part is executed you can test the Aiken verifier as follows:

```bash
cd aiken-verifier/aiken_halo2
aiken check
aiken build
```

### Benchmarks

Below are the execution costs of both Plinth and Aiken scripts running the Halo2 verifier for various circuits:

| Circuit description             | Script size*</br>Plinth | Script size*</br>Aiken | CPU usage*</br>Plinth | CPU usage*</br>Aiken | Mem usage*</br>Plinth | Mem usage*</br>Aiken | 
|---------------------------------|-------------------------|------------------------|-----------------------|----------------------|-----------------------|----------------------|
| **Simple mul**                  |           6,699 (40.9%) |          6,610 (40.3%) |            5.8B (58%) |           5.3B (53%) |          9.0M (64.3%) |         5.6M (40.0%) |
| **Lookup table**                |          11.508 (70.2%) |         10,453 (63.8%) |            9.2B (92%) |           8.4B (84%) |         13.0M (92.9%) |         7.5M (53.6%) |
| **ATMS (50 out of 90)**         |          12,295 (75.0%) |         11,634 (71.0%) |          10.1B (101%) |           9.7B (97%) |         11.9M (85.0%) |         7.9M (56.4%) |
| **ATMS (228 out of 408)**       |          12,293 (75.0%) |         11,630 (71.0%) |          10.0B (100%) |           9.7B (97%) |         11.8M (84.3%) |        7. 8M (55.7%) |
| **ATMS (50/90) + lookup table** |          14,557 (88.9%) |         13,498 (82.4%) |          12.0B (120%) |         11.4B (114%) |       14. 7M (105.0%) |        9.0M  (64.3%) |
| **Schnorr signatures**          |         20,474 (125.0%) |        18,910 (115.4%) |          13.0B (130%) |         12.4B (124%) |       15.7M  (112.1%) |       10.2M (72 .9%) |


\* Script size % is taken as a percentage of the 16kib script limit, CPU max is 10B and Mem max is 14M.

**Note that the benchmark numbers are approximate.** Even for the same circuit, the verifier's execution cost may vary
slightly depending on the specific proof being verified. This variation stems from the randomness used during proof
generation, which can be influenced by the initial seed or the platform on which the prover runs.

#### Further improvements

The upcoming CIP-109 (built-in modular inversion) and CIP-133 (built-in multi-scalar multiplication) are expected to
significantly reduce the on-chain costs of the verifiers.

## Cost Estimator

The Cost Estimator predicts verifier execution costs from circuit parameters, without requiring a full circuit
run. This is useful for quickly gauging whether a circuit is likely to fit within Cardano's execution limits.
It only requires the Rust component — no Plinth or Aiken toolchain needed.

Three CLI binaries are available:

| Binary | Output |
|---|---|
| `estimate` | Full breakdown: scalar/point ops, pairings, MSM sizes, proof and VK byte sizes |
| `proof_size` | Proof size in bytes |
| `vk_size` | Verification key size in bytes |

> **Note:** Estimates are lower bounds, assuming minimal column rotations (prev, current, next).

### CLI flags

All three binaries share the same flags:

```
Proof inputs :
  --nb-public-inputs / --pi        Number of public inputs (required)
  --committed-instances / --ci     If any committed instances
  --recursion / --rec              Whether we are doing recursion

Chips (combine as needed):
  --native          Native arithmetic chip (arithmetic + parallel_add gates)
  --automaton       Regular expression parsing (automaton) chip
  --base64          Base64 decoding chip
  --sha256          SHA256 hash chip
  --sha512          SHA512 hash chip
  --poseidon        Poseidon hash chip
  --jubjub          Jubjub Edwards curve chip
  --bls12-381       BLS12-381 curve chip
  --curve25519      Curve25519 curve chip
  --secp256k1       Secp256k1 curve chip
  --secp256r1       Secp256r1 curve chip
  --hash-to-curve   Poseidon hash-to-Jubjub-curve chip

Circuit config (all default to 0):
  --nb-advice       Number of advice columns
  --nb-fixed        Number of extra fixed columns
  --nb-selectors    Number of extra selectors
  --nb-evaluations  Number of column evaluations
  --nb-lookups      Number of lookup arguments
  --degree          Circuit degree
  --nr-pow2         Number of pow2-range decomposition columns
```

The chips' flags are the main and most precise way for evaluating circuits.

We also provide additional circuit configuration to help user analyse the circuit verification's cost when handling additional advice and fixed columns/wires, or selectors, or when needing a higher degree.
The number of evaluations on these additional columns and extra lookups also permit more customization but the estimate becomes looser because of the limited amount of information provided, more information would be required but this would make the CLI less usable.
The `nr-pow2` stands for the number of parralel lookups for scalar decomposition we allow to perform in circuit. This increases the number of arguments, hence the proof size and verification cost, but not the verification key's size. If the value is not set, the program chooses the maximum value defined by the used chips.

### Examples

```bash
# Full cost estimate: 3 public inputs, native chip
cargo run --bin estimate -- --nb-public-inputs 3 --native

# Proof size for a circuit with Poseidon hashing and Jubjub signatures
cargo run --bin proof_size -- --nb-public-inputs 5 --committed-instances --poseidon --jubjub

# Full estimate for a circuit with hash-to-curve and lookup arguments
cargo run --bin estimate -- --nb-public-inputs 2 --hash-to-curve --nb-lookups 2 --degree 8
```

## License

Copyright 2025 Input Output Global

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this repository except in compliance
with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "
AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License
