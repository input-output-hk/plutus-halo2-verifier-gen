# Halo2 Verifier Profiling Setup

This directory contains tools for profiling and benchmarking the generated Plinth and Aiken Halo2 verifiers. Profiling
helps analyze CPU and memory usage breakdown of the on-chain verification scripts.

## Overview

The profiling tooling uses Plutus UPLC (Untyped Plutus Core) evaluation with budget tracking to measure:

- **CPU usage**: Computational costs per operation
- **Memory usage**: Memory consumption per operation
- **Execution traces**: Detailed breakdown of which functions consume the most resources

Profiling results are visualized as **flame graphs** (`cpu.svg` and `mem.svg`) showing the call stack and resource
usage.

## Prerequisites

- **Nix**: Required to run the Plutus UPLC evaluator and profiling tools
- **jq**: JSON processor for extracting compiled code
- **xxd**: Hex dump utility for binary conversion

## How to Use the Profiler

### Step 1: Generate Verifier Code

Generate both Aiken and Plinth verifier code by running a Rust example circuit:

```bash
# From the repository root
cargo run --example atms
```

This generates:

- Aiken verifier: `aiken-verifier/aiken_halo2/lib/proof_verifier.ak` and `validators/profiler.ak`
- Plinth verifier: `plinth-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/Verifier.hs`

You can use any example circuit (`simple_mul`, `atms`, `lookup_table`, `atms_with_lookups`).

### Step 2: Build Aiken Verifier

Build the Aiken project to generate the compiled Plutus script:

```bash
cd aiken-verifier/aiken_halo2
aiken build
```

This creates `plutus.json` containing the compiled validator. The profiler extracts the compiled code from the
first validator which should be `profiler.halo2_profiler.else`.

### Step 3: Build Plinth Verifier

Build the Plinth project using Nix and Cabal:

```bash
nix develop github:input-output-hk/devx#ghc96-iog
cd plinth-verifier
cabal test all
```

This generates `plinth-verifier/plutus-halo2/VerifierScript.flat` - the compiled UPLC script.

### Step 4: Run the Profiler

Execute the profiling script:

```bash
cd profiling_setup
./profiling.sh
```

## How It Works

The profiling script performs the following steps:

### For Aiken Verifier:

1. **Extract compiled code**: Uses `jq` to extract the first validator from `plutus.json`
2. **Convert to CBOR**: Converts hex-encoded contract to CBOR binary format
3. **Extract FLAT encoding**: Skips the 3-byte CBOR header to get the raw UPLC FLAT encoding
4. **Apply unit argument**: The compiled Aiken profiler validator from `profiler.ak` is applied to `unit.flat` which is
   just UPLC-compiled `(program 1.1.0(con unit ()))`
5. **Evaluate with budgets**: Runs `uplc evaluate` with `--trace-mode LogsWithBudgets` to capture detailed execution
   traces
6. **Generate flame graphs**: Processes traces through `traceToStacks` and `flamegraph` to create visual profiles

### For Plinth Verifier:

1. **Evaluate directly**: The Plinth `VerifierScript.flat` is already in the correct format (includes arguments)
2. **Use named DeBruijn format**: Evaluates with `--if flat-namedDeBruijn` for better readability
3. **Track budgets**: Uses the same `--trace-mode LogsWithBudgets` for comparable metrics

## Output Files

After running the profiler, the following files are generated:

- **`contract.hex`**: Hex-encoded Aiken validator extracted from `plutus.json`
- **`contract.cbor`**: Binary CBOR-encoded validator
- **`script.flat`**: UPLC FLAT encoding of the Aiken validator (after header removal)
- **`script2.flat`**: Aiken validator with `unit` argument applied
- **`cpu.svg`**: Flame graph visualization of CPU usage
- **`mem.svg`**: Flame graph visualization of memory usage
- **`logs`**: Raw execution trace logs with budget information