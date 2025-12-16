#!/bin/sh

jq -r '.validators[0].compiledCode' aiken-verifier/aiken_halo2/plutus.json  > contract.hex
xxd -r -p < contract.hex > contract.cbor

# skip header to get flat CBOR
SKIP=3

dd if=contract.cbor of=script.flat bs=1 skip=$SKIP 2>/dev/null

nix run github:IntersectMBO/plutus/1.55.0.0#uplc -- evaluate -t -i script.flat --if flat --trace-mode LogsWithBudgets -o logs
cat logs | nix run github:IntersectMBO/plutus/1.30.0.0#traceToStacks | nix run nixpkgs#flamegraph > cpu.svg
cat logs | nix run github:IntersectMBO/plutus/1.30.0.0#traceToStacks -- --column 2 | nix run nixpkgs#flamegraph > mem.svg``
