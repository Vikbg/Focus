#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION = ROOT / ".github" / "workflows" / "foundation.yml"
DEPENDENCY_SECURITY = ROOT / ".github" / "workflows" / "dependency-security.yml"
WORKFLOWS = ROOT / ".github" / "workflows"


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def require_fragments(
    text: str,
    fragments: list[tuple[str, str]],
    failures: list[str],
) -> None:
    for fragment, message in fragments:
        require(fragment in text, message, failures)


def main() -> int:
    failures: list[str] = []

    require((ROOT / "Cargo.lock").is_file(), "Cargo.lock must be committed", failures)
    require((ROOT / "pnpm-lock.yaml").is_file(), "pnpm-lock.yaml must be committed", failures)
    require(DEPENDENCY_SECURITY.is_file(), "dependency security workflow must exist", failures)

    foundation = FOUNDATION.read_text(encoding="utf-8")
    require_fragments(
        foundation,
        [
            ("- \"main\"", "Foundation must run on pushes to main"),
            ("cargo check --workspace --all-targets --locked", "cargo check must use --locked"),
            ("cargo test --workspace --locked", "cargo test must use --locked"),
            (
                "cargo clippy --workspace --all-targets --locked -- -D warnings",
                "Clippy must use --locked",
            ),
            ("pnpm install --frozen-lockfile", "pnpm install must use --frozen-lockfile"),
            ("pnpm -r lint", "JavaScript lint must be required"),
            ("pnpm -r typecheck", "JavaScript typecheck must be required"),
            ("pnpm -r test", "JavaScript tests must be required"),
        ],
        failures,
    )

    dependency_security = DEPENDENCY_SECURITY.read_text(encoding="utf-8")
    require_fragments(
        dependency_security,
        [
            ("- \"main\"", "Dependency security must run on pushes to main"),
            ("cargo-audit --version 0.22.2 --locked", "cargo-audit must be pinned"),
            ("cargo-deny --version 0.20.2 --locked", "cargo-deny must be pinned"),
            ("cargo audit", "cargo audit must be required"),
            ("cargo deny check", "cargo deny check must be required"),
            ("pnpm install --frozen-lockfile", "security pnpm install must be frozen"),
            ("pnpm audit", "pnpm audit must be required"),
        ],
        failures,
    )

    mutable_action = re.compile(r"^\s*uses:\s*[^@\s]+@v\d+(?:\s|$)", re.MULTILINE)
    immutable_action = re.compile(r"^\s*uses:\s*[^@\s]+@[0-9a-f]{40}(?:\s+#.*)?$", re.MULTILINE)
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        require(
            mutable_action.search(text) is None,
            f"{workflow.relative_to(ROOT)} contains a mutable major action tag",
            failures,
        )
        for line in text.splitlines():
            if "uses:" in line:
                require(
                    immutable_action.match(line) is not None,
                    f"{workflow.relative_to(ROOT)} action is not pinned to a 40-hex commit: {line.strip()}",
                    failures,
                )

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        return 1

    print("CI reproducibility policy satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
