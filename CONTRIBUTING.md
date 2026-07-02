# Contributing

## Prerequisites

- **Rust** (stable toolchain, see `rust-toolchain.toml`)
- **wasm-pack** — for rebuilding the WASM module used by the web interface:
  ```sh
  cargo install wasm-pack
  ```
- **Node.js / a local HTTP server** — only needed to serve the docs locally; any static server works

## Build

```sh
# Build the native library and CLI
cargo build

# Run all tests
cargo test

# Format all Rust sources
cargo fmt
```

## Project structure

```
src/bin                       # Cost estimator CLI commands and chip profile writers
src/circuits                  # Halo2 circuits, used in examples
src/plutus_gen/adjusted_types # Halo2 adjusted types
src/plutus_gen/extraction     # Halo2 vk extraction utilities
src/plutus_gen/emitters       # Aiken/Plinth Halo2 verifier generator
src/plutus_gen/stats/chips/   # Chip definitions (cost estimator)
  mod.rs                      # SupportedChips enum, Chip trait, dispatch macro
  primitives/                 # Concrete chip implementations
    native.rs                 # Base arithmetic chip
    hash/                     # Hash chips (Poseidon, …)
    curve/                    # ECC chips (JubJub, BLS12-381, secp256k1, …)
src/plutus_gen/cli.rs         # CLI argument parsing
src/plutus_gen/proof_seria.   # Proof serialization
src/kzg_params                # CRS / powers of tau utils
src/wasm.rs                   # WASM bindings for the web interface
docs/                         # Static website (cost estimator, chip reference)
  chip_profiles.json          # Generated — do not edit by hand
  wasm/                       # Generated WASM artifacts — rebuild with wasm-pack
```

## Adding a Halo2 subprofotocol

### Adding a PCS

Polynomial Commitment Schemes structure needs to implement the `ExtractPCS` trait defined in `src/plutus_gen/extraction/pcs/mod.rs` for the smart contract code generation, as well as the `PcsEstimate` `trait defined in src/plutus_gen/stats/pcs/mod.rs` for the cost estimator.

For the latter, the website, CLI and wasm would also need to be modified to support new commitment schemes.

### Adding a Lookup scheme

Lookup are currently coded directly in the main extraction file `src/plutus_gen/extraction/mod.rs` and as such, to support new lookups, an modular architecture similar to PCS needs to be implemented first (define a generic lookup trait in a new folder, move the Plookup code and update it to instantiate such trait and call the input lookup scheme in `.../extraction/mod.rs`).

For the cost estimator, the new scheme needs to be coded in `src/plutus_gen/stats/lookup` and implement the `LookupEstimate` in `.../lookup/mod.rs` file. Similarly to before, the website, CLI and wasm needs to be modified to support new lookup schemes.

## Adding a new chip

The full walkthrough with annotated code examples is in the documentation:

**[docs/contributing.html](docs/contributing.html)** — open in a browser after cloning, or visit the hosted version.

Quick summary of the eight steps:

1. Create `src/plutus_gen/stats/chips/primitives/<dir>/<my_chip>.rs` implementing the `Chip` trait
2. Re-export from `primitives/mod.rs`
3. Add a variant to the `SupportedChips` enum in `chips/mod.rs`
4. Add the variant to the `impl_supported_chips!` macro invocation in the same file
5. Add a `--my-chip` boolean flag to `EstimateCliArguments` in `cli.rs`
6. Add a string match arm to `chip_from_str` in `wasm.rs`
7. Regenerate `docs/chip_profiles.json`:
   ```sh
   cargo run --bin dump_profiles
   ```
8. Rebuild the WASM module:
   ```sh
   wasm-pack build --target web --out-dir docs/wasm
   ```

Commit the updated `docs/chip_profiles.json` and `docs/wasm/` alongside your Rust changes.

## Code style

- Run `cargo fmt` before committing — CI enforces formatting
- No new `#[allow(…)]` suppressions without a comment explaining why
- Prefer `/// doc comment` over inline comments for public items

## Testing

```sh
cargo test
```

The test suite covers cost estimation correctness. If you add a chip, add a test that
compares the estimated proof size against a real proof generated from a circuit that uses
the chip. See the existing tests in `src/plutus_gen/stats/` for the pattern.

## Submitting changes

1. Fork the repository and create a branch from `main`
2. Make your changes, following the checklist in `docs/contributing.html`
3. Open a pull request against `main` with a clear description of what the chip models and
   where the column / gate counts come from

## Disclaimer

This repository contains proof-of-concept code for research purposes. See [README.md](README.md)
for the full disclaimer before submitting production-targeted changes.
