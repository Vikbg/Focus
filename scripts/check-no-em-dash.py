#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import subprocess
import sys

FORBIDDEN = chr(0x2014)


def tracked_files() -> list[pathlib.Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [pathlib.Path(p) for p in result.stdout.decode().split("\0") if p]


def main() -> int:
    violations: list[str] = []

    for path in tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        for line_number, line in enumerate(text.splitlines(), start=1):
            if FORBIDDEN in line:
                violations.append(f"{path}:{line_number}")

    if violations:
        print("Forbidden U+2014 character found:")
        for violation in violations:
            print(f"  {violation}")
        return 1

    print("No forbidden U+2014 character found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
