#!/usr/bin/env python3
import pathlib
import sys


def fail(message: str) -> None:
    print(f"verify-release-binary-trust: {message}", file=sys.stderr)
    raise SystemExit(1)


if len(sys.argv) != 6:
    fail("usage: verify-release-binary-trust.py BINARY REPLAY_HOSTNAME REPLAY_PINS CHECKPOINT_AUDIT_HOSTNAME CHECKPOINT_AUDIT_PINS")

binary = pathlib.Path(sys.argv[1])
hostname = sys.argv[2]
pins = sys.argv[3].split(",")
audit_hostname = sys.argv[4]
audit_pins = sys.argv[5].split(",")

if not binary.is_file() or binary.is_symlink():
    fail(f"binary is missing or is a symlink: {binary}")

data = binary.read_bytes()
for label, value in [
    ("replay-authority hostname", hostname),
    *[("replay-authority SPKI pin", pin) for pin in pins],
    ("checkpoint-audit hostname", audit_hostname),
    *[("checkpoint-audit SPKI pin", pin) for pin in audit_pins],
]:
    if not value or value.encode("ascii") not in data:
        fail(f"{label} is not embedded in {binary.name}")

print(f"{binary.name}: approved replay and checkpoint-audit anchors present")
