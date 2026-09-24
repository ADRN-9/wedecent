# Windows update trust boundary

WeDecent's Windows release pipeline now produces signed, immutable release and installer
archives. Update discovery adds a different trust problem: a client needs a small mutable
record that says which immutable version it should consider next without allowing the
download origin, CDN, cache, or an older still-valid record to redirect it to arbitrary
bytes.

This document defines the current update-protocol boundary. It does **not** enable automatic
background polling or installer execution yet.

## Stable channel manifest

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

## Signature file

The manifest is signed over its exact canonical bytes with Ed25519. The detached
signature file is the 64-byte Ed25519 signature encoded with unpadded URL-safe base64 and
a trailing LF. Verification accepts an LF or CRLF line ending on the detached signature
file, but the manifest bytes themselves must match the canonical representation exactly.

The production private update-signing key must remain outside this repository and outside
release artifacts. The verification API requires the caller to supply a pinned Ed25519
public key; this repository does **not** embed a production update public key in this
slice. Production provisioning must not trust a key delivered beside the manifest, from
DNS, from the download origin, or through trust-on-first-use.

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

- publish the mutable stable-channel manifest/signature objects;
- embed or provision the production Ed25519 public key;
- schedule or automatically poll for updates;
- automatically advance sequence state after discovery;
- download a release or installer archive for application;
- launch PowerShell or execute an installer;
- stop, replace, or restart any running WeDecent process;
- create a scheduled task, service, or background updater.

Those behaviors should remain separate reviewable boundaries so key provisioning,
manifest publication, download verification, installer preflight, process ownership,
sequence commit timing, and recovery can each fail closed independently.
