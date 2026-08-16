#!/usr/bin/env bash
set -euo pipefail

manifest="crates/focus-core/Cargo.toml"
backup="$(mktemp)"
output="$(mktemp)"
cp "$manifest" "$backup"
restore() {
  cp "$backup" "$manifest"
  rm -f "$backup" "$output"
}
trap restore EXIT

python3 - <<'PY'
from pathlib import Path

path = Path("crates/focus-core/Cargo.toml")
text = path.read_text(encoding="utf-8")
old = 'sha2 = "0.11"'
new = 'sha2 = "=0.10.9"'
if old not in text:
    raise SystemExit("expected sha2 dependency declaration not found")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY

if cargo check -p focus-core --locked >"$output" 2>&1; then
  cat "$output"
  echo "ERROR: cargo --locked accepted a dependency manifest change without a lockfile update"
  exit 1
fi

if ! grep -Eq "lock file .* needs to be updated|Cargo.lock needs to be updated|needs to be updated but --locked was passed|cannot update the lock file .* because --locked was passed" "$output"; then
  cat "$output"
  echo "ERROR: locked build failed for an unexpected reason"
  exit 1
fi

echo "Cargo lock enforcement verified."
