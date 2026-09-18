#!/usr/bin/env bash
# Build the browser front end into docs/pkg.
#
#   scripts/build-web.sh          release build
#   OPT=debug scripts/build-web.sh
#
# Output lands in docs/, which is where GitHub Pages serves from, so the built artefact is
# committed. It is 216 KB and rebuilding it in CI would mean pinning a wasm-bindgen version
# in two places.
#
# Requires: rustup target add wasm32-unknown-unknown && cargo install wasm-bindgen-cli
# The wasm-bindgen crate version is pinned to the CLI's; a mismatch fails loudly at
# bindgen time rather than subtly at runtime.
set -euo pipefail
cd "$(dirname "$0")/.."

OPT=${OPT:-release}
FLAG=""
[ "$OPT" = release ] && FLAG="--release"

command -v wasm-bindgen >/dev/null || { echo "cargo install wasm-bindgen-cli" >&2; exit 1; }

cargo build -p elfa-web --target wasm32-unknown-unknown $FLAG
wasm-bindgen --target web --no-typescript \
  --out-dir docs/pkg \
  "target/wasm32-unknown-unknown/$OPT/elfa_web.wasm"

echo "docs/pkg  $(du -sh docs/pkg | cut -f1)"
ls -la docs/pkg/*.wasm
