# Windows update trust boundary

WeDecent's Windows release pipeline now produces signed, immutable release and installer
archives. Update discovery adds a different trust problem: a client needs a small mutable
record that says which immutable version it should consider next without allowing the
download origin, CDN, cache, or an older still-valid record to redirect it to arbitrary
bytes.

This document defines the current update-protocol boundary. It does **not** enable automatic
background polling or installer execution yet.

## Current protocol — C316 schema-v2 stable channel (2026-11-26)

**This section is authoritative and supersedes the historical schema-v1 sections below.** The v1 examples and tooling notes are retained only to explain legacy compatibility tests. Production stable discovery and publication must not use manifest-v1 or the old two-object stable pair.

The current stable manifest is schema v2. It includes the active `signing_key_id` and `keyset_epoch` in addition to the channel, sequence, version, publication time and immutable artifact hashes/URLs. It is canonical JSON and is signed over its exact bytes with Ed25519. A v2 manifest without an authorized active key in the referenced root-signed keyset is rejected. There is no automatic v1 fallback.

The client fetches one stable object:

```text
https://downloads.wedecent.com/windows/stable/current-v2.json
```

That canonical envelope contains both the exact canonical manifest bytes and its detached Ed25519 signature, encoded as unpadded base64url fields. This single object is the stable publication pointer; readers cannot observe a new manifest with an old signature or vice versa. The client strictly parses the envelope and v2 manifest before deriving the immutable keyset path from the untrusted epoch field:

```text
https://downloads.wedecent.com/windows/stable/keysets/{epoch}/keyset.json
https://downloads.wedecent.com/windows/stable/keysets/{epoch}/keyset.sig
```

The keyset is signed by the independently pinned Ed25519 root key. Its epoch, digest, validity, root ID, key IDs, key status and revocation state are verified. The keyset is persisted through `StateStore.VerifyAndAdvanceKeyset` under the same cross-process updater lock used by manifest sequence advancement and installer application. Lower epochs and same-epoch equivocation are rejected. The manifest must reference the exact verified epoch and an active signing key. Keyset epoch/digest are retained in protected state schema v2; successful installer application advances the manifest sequence while preserving the keyset fields.

Stable publication first creates immutable epoch keyset objects using conditional create-only R2 writes. It then publishes `current-v2.json` as one R2 object with S3 `PutObject If-None-Match: *` for initial creation or `PutObject If-Match: <observed ETag>` for replacement. A single object is the atomic commit point. The publisher verifies the prior object hash against the independent verifier receipt, uses a unique `writeid` metadata value to reconcile ambiguous responses, retries the identical conditional request, and reads back exact committed bytes. A competing writer is never overwritten; an unresolved response fails closed and requires inspection of the object `writeid` before retrying.

The production workflow is split into signer, public-key verifier and R2 publisher jobs. The signer has no R2 publication credentials; the verifier has neither signing nor R2 credentials and hashes signed inputs before/after verification; the publisher has R2 write credentials but no signer identity. Repository CI includes restricted-credential cross-operation tests, separate ephemeral Linux UID/0600-file tests, and a fake R2 conditional-write race regression.

**Production activation remains blocked** until the root public key is pinned in shipped clients, the offline root/keyset provisioning ceremony is approved, R2 publisher-only credentials and least-privilege bucket policy are provisioned, actual production runner host/OS-account/admin separation is evidenced, GitHub environment reviewers and branch governance are hardened, and live R2 concurrent-writer/read-back plus production client E2E tests pass. The current repository branch has no production root key or production signing secret. The v1 client/state migration gate is also required before v2 stable activation. The `DiscoveryClient` implementation is present, but no production UI/agent update-polling call site or end-to-end installer handoff has been demonstrated in C316.

---

## Legacy schema-v1 stable manifest (historical; not production)

The stable channel uses a canonical JSON manifest authenticated by a detached Ed25519
signature. The current schema is version 1:

```json
{"schema":1,"channel":"stable","sequence":42,"version":"v1.2.3","published_at":"2026-09-23T20:00:00Z","release_url":"https://downloads.wedecent.com/windows/v1.2.3/wedecent-v1.2.3-windows-amd64.zip","release_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","installer_url":"https://downloads.wedecent.com/windows/v1.2.3/wedecent-v1.2.3-windows-installer.zip","installer_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
```

The canonical representation has exactly one trailing LF and no other insignificant
whitespace. Field order is fixed by the schema. Unknown fields, duplicate fields,
additional JSON values, alternate whitespace/order, and manifests larger than 16 KiB are
rejected rather than normalized before signature verification.

`internal/updateinfo` owns this encoding and validation contract.

### Fields

- `schema` must be `1`.
- `channel` must be `stable`.
- `sequence` is a positive, monotonically increasing unsigned integer. It is independent
  of the human-readable version and exists to support rollback resistance.
- `version` is strict stable `vMAJOR.MINOR.PATCH`. Version 1 deliberately does not permit
  prerelease or build metadata in the stable channel.
- `published_at` is canonical UTC RFC 3339 at whole-second precision, for example
  `2026-09-23T20:00:00Z`.
- `release_url` and `installer_url` are not arbitrary URLs. They must be the exact
  immutable version-derived paths on `https://downloads.wedecent.com`.
- `release_sha256` and `installer_sha256` are lowercase SHA-256 hex for the exact public
  ZIP bytes named by those URLs.

The manifest never contains credentials, local paths, executable arguments, alternate
hosts, redirect destinations, or installer command lines.

## Signature and public-key artifacts

The manifest is signed over its exact canonical bytes with Ed25519. The detached
signature file is the 64-byte Ed25519 signature encoded with unpadded URL-safe base64 and
a trailing LF. Verification accepts an LF or CRLF line ending on the detached signature
file, but the manifest bytes themselves must match the canonical representation exactly.

`internal/updateinfo.EncodePublicKey` / `DecodePublicKey` define the release-tooling public
key representation: the raw 32-byte Ed25519 public key encoded as one unpadded URL-safe
base64 line. Alternate whitespace and padded encodings are rejected. This file format is
a provisioning artifact, not a discovery mechanism.

The production private update-signing key must remain outside this repository and outside
release artifacts. The verification API requires the caller to supply a pinned Ed25519
public key; this repository still does **not** embed a production update public key.
Production provisioning must not trust a key delivered beside the manifest, from DNS,
from the download origin, or through trust-on-first-use.

## Stable-channel publication tooling

`scripts/publish-windows-stable-update.sh` provides the release-operator boundary for
preparing and publishing the mutable stable pair without taking custody of private key
material.

For a requested stable version and sequence it:

1. downloads the already-published immutable release and installer ZIPs from their exact
   canonical `downloads.wedecent.com` URLs and derives the SHA-256 values from those bytes;
2. invokes `cmd/wd-update-manifest` to create the canonical schema-v1 manifest using the
   same Go encoder used by clients;
3. invokes the absolute, non-symlink executable named by
   `WEDECENT_UPDATE_MANIFEST_SIGNER`, passing only the manifest path and destination
   signature path;
4. verifies the produced signature locally against an explicitly supplied canonical
   public-key file;
5. when a stable pair already exists, downloads and verifies both existing objects and
   rejects a candidate that does not advance both sequence and stable version;
6. delegates publication to the absolute, non-symlink executable named by
   `WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER`; and
7. downloads the resulting pair again, requires byte-for-byte equality with the prepared
   pair, and verifies the signature once more.

The private signer and storage credentials remain outside this repository. The publisher
hook receives the SHA-256 of both previously verified stable objects (or `-` for a clean
bootstrap) and must atomically compare those expected states and replace the manifest and
signature as one logical operation. A two-step unconditional overwrite of the signature
and manifest is **not** an acceptable implementation: a crash or competing publisher can
otherwise strand a mismatched pair. Publication is therefore fail-closed unless release
operations provide a storage primitive that implements the documented pair CAS contract.

`--dry-run` performs artifact hashing, canonical generation, signing, existing-state
verification, and rollback checks without invoking the pair publisher.

This tooling completes the repository-side publication boundary, but production rollout
still requires provisioning an actual production Ed25519 key pair, protecting the private
key in release operations, installing the corresponding public-key pin into clients through
an authenticated build/provisioning path, and providing the production atomic publisher
hook. No test key is a production trust anchor.

## Fixed-origin discovery

`internal/updateinfo.DiscoveryClient` retrieves exactly two stable-channel objects:

```text
https://downloads.wedecent.com/windows/stable/manifest-v1.json
https://downloads.wedecent.com/windows/stable/manifest-v1.sig
```

The URLs are constants, not caller input. Redirects are rejected rather than followed,
non-200 responses fail closed, and both response bodies are bounded before allocation.
The manifest is authenticated with the explicitly provisioned pinned Ed25519 public key
before any manifest fields are returned. A candidate must then pass `CheckAdvance`
against both the installed stable version and the caller-supplied highest accepted
sequence.

Discovery is deliberately read-only with respect to anti-rollback state. Fetching or
verifying a candidate does **not** persist its sequence. This matters because a download,
Authenticode check, installer preflight, or installation may still fail. Consuming the
sequence merely because a candidate was observed would make a safe retry of that same
signed release look like a rollback.

The fetcher preserves caller cancellation/deadline causes while also classifying failures
as update-discovery errors. It does not log or return response bodies.

## Rollback resistance and local state

A valid signature alone does not make an old signed manifest current. A client that has
accepted sequence `N` must persist `N` in protected local state and reject every later
manifest whose sequence is less than or equal to `N`.

For an update to be eligible, the candidate must advance both:

1. the highest previously accepted manifest sequence; and
2. the currently installed stable `vMAJOR.MINOR.PATCH` version.

`internal/updateinfo.CheckAdvance` implements the eligibility decision. Version components
are compared with arbitrary precision rather than machine integers.

`internal/updateinfo.StateStore` provides the separate monotonic commit primitive. The
state file is `update-state.json` under the caller-selected per-user client state
directory. Missing state means sequence zero. Persisted state is strict, canonical,
bounded JSON and contains only the storage version and highest accepted stable sequence.
It is non-secret; its purpose is rollback resistance, not confidentiality.

The store fails closed on symbolic links, non-regular files, malformed/alternate
encodings, and sequence decreases. On Unix-like systems the state file and containing
directory must be owned by the effective user and must not be accessible to group/other
users. Writes use a same-directory temporary file, file sync, atomic rename, and parent
directory sync. On Windows replacement uses `MoveFileExW` with replace-existing and
write-through semantics so advancing anti-rollback state does not require a
remove-then-rename window that could erase the previous sequence after a crash.

The store's mutex prevents races between callers sharing one `StateStore` instance. It is
not a cross-process compare-and-swap primitive. The eventual updater should have a single
process owner, or add an explicit OS-level interprocess lock before multiple updater
processes are introduced.

Sequence persistence prevents replay of an older signed record **after** a newer record
has been committed. It does not solve first-run freshness or a network adversary that
indefinitely suppresses every newer manifest. Discovery cadence, production key rotation,
and operational alerting for prolonged suppression remain separate policy decisions.

## Artifact verification remains independent

The signed channel manifest binds the intended immutable ZIP URLs and SHA-256 values. It
does not replace the existing release authenticity boundary.

Before any future updater executes installer content, it must still use the signed public
archive verification policy documented in `docs/PUBLIC_DOWNLOADS.md`:

- verify the downloaded installer ZIP against the manifest SHA-256;
- verify the installer package's exact shape and internal checksum manifests;
- verify Authenticode on the five executables and three PowerShell installer scripts
  using the approved WeDecent publisher/certificate-chain/timestamp policy;
- refuse to execute content that fails any of those checks.

This defense in depth means compromise of the update-manifest signing key alone does not
silently turn an arbitrary executable into a trusted WeDecent installer, and compromise
of the download origin alone cannot forge a valid channel manifest.

## Deliberately deferred

This slice does not:

- embed or provision the production Ed25519 public-key pin in client binaries;
- supply a production private signing key or production atomic-publisher implementation;
- schedule or automatically poll for updates;
- automatically advance sequence state after discovery;
- download a release or installer archive for application;
- launch PowerShell or execute an installer;
- stop, replace, or restart any running WeDecent process;
- create a scheduled task, service, or background updater.

Those behaviors should remain separate reviewable boundaries so key provisioning,
manifest publication, download verification, installer preflight, process ownership,
sequence commit timing, and recovery can each fail closed independently.
