#!/usr/bin/env python3
import pathlib
import sys


def fail(message: str) -> None:
    print(f"verify-release-binary-trust: {message}", file=sys.stderr)
    raise SystemExit(1)


if len(sys.argv) != 4:
    fail("usage: verify-release-binary-trust.py BINARY HOSTNAME COMMA_SEPARATED_SPKI_PINS")

binary = pathlib.Path(sys.argv[1])
hostname = sys.argv[2]
pins = sys.argv[3].split(",")

if not binary.is_file() or binary.is_symlink():
    fail(f"binary is missing or is a symlink: {binary}")

data = binary.read_bytes()
for label, value in [("hostname", hostname), *[("SPKI pin", pin) for pin in pins]]:
    if not value or value.encode("ascii") not in data:
        fail(f"{label} is not embedded in {binary.name}")

print(f"{binary.name}: approved replay-authority anchors present")
