#!/usr/bin/env python3
"""Create and verify content-addressed release provenance sidecars."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SCHEMA = "https://wedecent.com/schemas/release-provenance/v1"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ProvenanceError(Exception):
    pass


def fail(message: str) -> None:
    raise ProvenanceError(message)


def git_tree(repo_root: Path, commit: str) -> str:
    if not COMMIT_RE.fullmatch(commit):
        fail("source commit must be an exact lowercase 40-character Git SHA")
    result = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--verify", f"{commit}^{{tree}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail("cannot resolve the Git tree associated with the expected source commit")
    tree = result.stdout.strip()
    if not COMMIT_RE.fullmatch(tree):
        fail("Git returned a malformed source tree identifier")
    return tree


def parse_metadata(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        fail("VERSION.txt must be a regular non-symlink file")
    metadata: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[a-z][a-z0-9_]*", key) or key in metadata:
            fail("VERSION.txt contains malformed or duplicate metadata")
        metadata[key] = value
    return metadata


def artifact_files(directory: Path) -> list[dict[str, str]]:
    if directory.is_symlink() or not directory.is_dir():
        fail("artifact directory must be a regular non-symlink directory")
    entries: list[dict[str, str]] = []
    with os.scandir(directory) as scan:
        for entry in scan:
            if not NAME_RE.fullmatch(entry.name):
                fail(f"artifact contains an unsafe filename: {entry.name!r}")
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                fail(f"artifact entries must be regular non-symlink files: {entry.name}")
            digest = hashlib.sha256(Path(entry.path).read_bytes()).hexdigest()
            entries.append({"path": entry.name, "sha256": digest})
    entries.sort(key=lambda item: item["path"])
    if not entries or not {"VERSION.txt", "SHA256SUMS.txt"}.issubset(
        {item["path"] for item in entries}
    ):
        fail("artifact must contain VERSION.txt and SHA256SUMS.txt")
    return entries


def artifact_tree_digest(files: list[dict[str, str]]) -> str:
    canonical = b"".join(
        f"{item['path']}\0{item['sha256']}\n".encode("ascii") for item in files
    )
    return hashlib.sha256(canonical).hexdigest()


def validate_metadata(
    directory: Path,
    source_commit: str,
    source_tree: str,
    platform: str,
) -> None:
    metadata = parse_metadata(directory / "VERSION.txt")
    expected = {
        "commit": source_commit,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "build_mode": "production",
        "platform": platform,
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            fail(f"VERSION.txt {key} does not match verified release provenance")


def write_exclusive(path: Path, data: bytes) -> None:
    if path.is_symlink() or path.exists():
        fail(f"refusing to overwrite provenance output: {path}")
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink() or parent.resolve() != parent:
        fail("provenance output parent must be an existing canonical directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def create_provenance(
    repo_root: Path,
    directory: Path,
    output: Path,
    repository: str,
    source_commit: str,
    artifact_name: str,
    platform: str,
) -> dict[str, Any]:
    repo_root = repo_root.resolve(strict=True)
    if repository != "ADRN-9/wedecent":
        fail("release provenance can only be created for ADRN-9/wedecent")
    if not repo_root.is_dir():
        fail("repository root is not a directory")
    source_tree = git_tree(repo_root, source_commit)
    validate_metadata(directory, source_commit, source_tree, platform)
    files = artifact_files(directory)
    statement: dict[str, Any] = {
        "schema": SCHEMA,
        "repository": repository,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "artifact_name": artifact_name,
        "platform": platform,
        "files": files,
        "artifact_tree_sha256": artifact_tree_digest(files),
    }
    payload = (json.dumps(statement, sort_keys=True, separators=(",", ":")) + "\n").encode()
    write_exclusive(output, payload)
    return statement


def verify_provenance(
    repo_root: Path,
    directory: Path,
    provenance: Path,
    repository: str,
    expected_commit: str,
    artifact_name: str,
    platform: str,
) -> dict[str, Any]:
    repo_root = repo_root.resolve(strict=True)
    if repository != "ADRN-9/wedecent":
        fail("release provenance repository is not ADRN-9/wedecent")
    if provenance.is_symlink() or not provenance.is_file():
        fail("provenance statement must be a regular non-symlink file")
    try:
        statement = json.loads(provenance.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"provenance statement is not valid UTF-8 JSON: {error}")
    expected_keys = {
        "schema",
        "repository",
        "source_commit",
        "source_tree",
        "artifact_name",
        "platform",
        "files",
        "artifact_tree_sha256",
    }
    if not isinstance(statement, dict) or set(statement) != expected_keys:
        fail("provenance statement has an unexpected schema")
    if statement["schema"] != SCHEMA:
        fail("unsupported provenance schema")
    if statement["repository"] != repository:
        fail("provenance repository does not match the trusted repository")
    if statement["source_commit"] != expected_commit:
        fail("provenance source commit does not match immutable GITHUB_SHA")
    if statement["artifact_name"] != artifact_name or statement["platform"] != platform:
        fail("provenance artifact identity does not match the expected artifact")
    actual_tree = git_tree(repo_root, expected_commit)
    if statement["source_tree"] != actual_tree:
        fail("provenance source tree does not match the Git tree associated with immutable GITHUB_SHA")
    validate_metadata(directory, expected_commit, actual_tree, platform)

    files = statement["files"]
    if not isinstance(files, list) or not files:
        fail("provenance file digest list is missing")
    previous = ""
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            fail("provenance file entry has an unexpected schema")
        name = item["path"]
        digest = item["sha256"]
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name <= previous:
            fail("provenance file entries must be uniquely sorted safe filenames")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            fail(f"provenance digest is malformed for {name}")
        previous = name

    actual_files = artifact_files(directory)
    if files != actual_files:
        fail("artifact files or SHA-256 digests differ from the attested provenance statement")
    if statement["artifact_tree_sha256"] != artifact_tree_digest(actual_files):
        fail("artifact tree digest does not match the verified file digests")
    return statement


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--repo-root", type=Path, required=True)
    create.add_argument("--directory", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--repository", required=True)
    create.add_argument("--source-commit", required=True)
    create.add_argument("--artifact-name", required=True)
    create.add_argument("--platform", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--repo-root", type=Path, required=True)
    verify.add_argument("--directory", type=Path, required=True)
    verify.add_argument("--provenance", type=Path, required=True)
    verify.add_argument("--repository", required=True)
    verify.add_argument("--expected-commit", required=True)
    verify.add_argument("--artifact-name", required=True)
    verify.add_argument("--platform", required=True)

    args = parser.parse_args()
    try:
        if args.command == "create":
            statement = create_provenance(
                args.repo_root,
                args.directory,
                args.output,
                args.repository,
                args.source_commit,
                args.artifact_name,
                args.platform,
            )
            print(f"Created {args.artifact_name} provenance: {statement['artifact_tree_sha256']}")
        else:
            statement = verify_provenance(
                args.repo_root,
                args.directory,
                args.provenance,
                args.repository,
                args.expected_commit,
                args.artifact_name,
                args.platform,
            )
            print(f"Verified {args.artifact_name} provenance: {statement['artifact_tree_sha256']}")
    except (OSError, ProvenanceError, subprocess.SubprocessError) as error:
        print(f"release-provenance: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
