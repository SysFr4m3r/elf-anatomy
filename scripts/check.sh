#!/usr/bin/env bash
# Everything CI checks, in the order CI checks it.
#
# The fmt check goes first because it is the cheapest and the easiest to forget: editing a
# crate and running only test and clippy leaves formatting behind, and CI fails on the one
# thing that takes a second to fix.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "· fmt"
cargo fmt --all -- --check

echo "· clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "· test"
cargo test --workspace --quiet

echo "· no_std"
cargo build -p elfa-parse --no-default-features --target x86_64-unknown-none --quiet

echo "all clean"
