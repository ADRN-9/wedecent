#!/usr/bin/env python3
"""Negative and positive tests for release provenance sidecars."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "release-provenance.py"
SPEC = importlib.util.spec_from_file_location("release_provenance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def run_git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def expect_rejected(label: str, callback) -> None:
    try:
        callback()
    except MODULE.ProvenanceError:
        return
    raise AssertionError(f"{label} was accepted")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="wedecent-provenance-test-") as temporary:
        work = Path(temporary)
        repo = work / "repo"
        artifact = work / "artifact"
        output = work / "provenance.json"
        repo.mkdir()
        artifact.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        run_git(repo, "config", "user.name", "WeDecent provenance tests")
        run_git(repo, "config", "user.email", "provenance-tests@example.invalid")
        (repo / "source.txt").write_text("source commit one\n", encoding="utf-8")
        run_git(repo, "add", "source.txt")
        run_git(repo, "commit", "-qm", "source one")
        first_commit = run_git(repo, "rev-parse", "HEAD")
        first_tree = run_git(repo, "rev-parse", "HEAD^{tree}")

        (artifact / "wd-core").write_bytes(b"core artifact bytes\n")
        (artifact / "SHA256SUMS.txt").write_text(
            f"{hashlib.sha256((artifact / 'wd-core').read_bytes()).hexdigest()}  wd-core\n",
            encoding="utf-8",
        )
        (artifact / "VERSION.txt").write_text(
            "\n".join(
                [
                    "version=0.0.0-test",
                    f"commit={first_commit}",
                    f"source_commit={first_commit}",
                    f"source_tree={first_tree}",
                    "build_mode=production",
                    "platform=linux/amd64",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        statement = MODULE.create_provenance(
            repo, artifact, output, "ADRN-9/wedecent", first_commit,
            "wedecent-linux-amd64", "linux/amd64",
        )
        MODULE.verify_provenance(
            repo, artifact, output, "ADRN-9/wedecent", first_commit,
            "wedecent-linux-amd64", "linux/amd64",
        )
        assert statement["source_tree"] == first_tree
        assert len(statement["artifact_tree_sha256"]) == 64

        original_binary = (artifact / "wd-core").read_bytes()
        (artifact / "wd-core").write_bytes(b"substituted artifact bytes\n")
        expect_rejected(
            "substituted artifact bytes",
            lambda: MODULE.verify_provenance(
                repo, artifact, output, "ADRN-9/wedecent", first_commit,
                "wedecent-linux-amd64", "linux/amd64",
            ),
        )
        (artifact / "wd-core").write_bytes(original_binary)

        original_statement = output.read_text(encoding="utf-8")
        forged_tree = json.loads(original_statement)
        forged_tree["source_tree"] = "c" * 40
        output.write_text(json.dumps(forged_tree), encoding="utf-8")
        expect_rejected(
            "forged source tree",
            lambda: MODULE.verify_provenance(
                repo, artifact, output, "ADRN-9/wedecent", first_commit,
                "wedecent-linux-amd64", "linux/amd64",
            ),
        )
        output.write_text(original_statement, encoding="utf-8")

        (artifact / "unexpected.bin").write_bytes(b"unlisted file\n")
        expect_rejected(
            "unlisted artifact file",
            lambda: MODULE.verify_provenance(
                repo, artifact, output, "ADRN-9/wedecent", first_commit,
                "wedecent-linux-amd64", "linux/amd64",
            ),
        )
        (artifact / "unexpected.bin").unlink()

        (repo / "source.txt").write_text("source commit two\n", encoding="utf-8")
        run_git(repo, "add", "source.txt")
        run_git(repo, "commit", "-qm", "source two")
        second_commit = run_git(repo, "rev-parse", "HEAD")
        expect_rejected(
            "substituted source commit",
            lambda: MODULE.verify_provenance(
                repo, artifact, output, "ADRN-9/wedecent", second_commit,
                "wedecent-linux-amd64", "linux/amd64",
            ),
        )

        (artifact / "VERSION.txt").write_text(
            (artifact / "VERSION.txt").read_text(encoding="utf-8").replace(
                f"source_tree={first_tree}", f"source_tree={'d' * 40}"
            ),
            encoding="utf-8",
        )
        expect_rejected(
            "forged VERSION.txt source tree",
            lambda: MODULE.create_provenance(
                repo, artifact, work / "forged.json", "ADRN-9/wedecent", first_commit,
                "wedecent-linux-amd64", "linux/amd64",
            ),
        )

    print("Release provenance positive and negative tests passed.")


if __name__ == "__main__":
    main()
