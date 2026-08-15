#!/usr/bin/env bash
set -euo pipefail

manifest="crates/focus-core/Cargo.toml"
backup="$(mktemp)"
cp "$manifest" "$backup"
restore() {
  cp "$backup" "$manifest"
  rm -f "$backup"
}
trap restore EXIT

printf '\nserde = "1"\n' >> "$manifest"

if cargo check -p focus-core --locked >/tmp/focus-lock-enforcement.out 2>&1; then
  cat /tmp/focus-lock-enforcement.out
  echo "ERROR: cargo --locked accepted a manifest change without a lockfile update"
  exit 1
fi

if ! grep -Eq "lock file .* needs to be updated|Cargo.lock needs to be updated|needs to be updated but --locked was passed" /tmp/focus-lock-enforcement.out; then
  cat /tmp/focus-lock-enforcement.out
  echo "ERROR: locked build failed for an unexpected reason"
  exit 1
fi

echo "Cargo lock enforcement verified."
