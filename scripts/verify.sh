#!/usr/bin/env bash
set -euo pipefail

python3 scripts/check-no-em-dash.py
python3 scripts/check-ci-reproducibility.py
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
bash scripts/check-lock-enforcement.sh
pnpm install --frozen-lockfile
pnpm -r lint
pnpm -r typecheck
pnpm -r test
