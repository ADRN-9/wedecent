# Windows installer update staging

This document defines the first artifact-download boundary of the signed Windows update flow. It does **not** execute an installer, advance anti-rollback sequence state, stop or restart WeDecent processes, or provision the production update trust key.

`internal/updateinfo.InstallerClient` consumes an already-authenticated schema-v1 `updateinfo.Manifest`. The caller is responsible for obtaining that manifest through the fixed-origin signed discovery path and applying the installed-version / sequence rollback checks before staging.

## Download boundary

`InstallerClient.Stage`:

- revalidates the manifest before using any URL or hash;
- requests only the manifest's canonical immutable `https://downloads.wedecent.com/windows/<version>/...-windows-installer.zip` URL;
- rejects redirects and every non-200 response;
- applies a two-minute default request timeout unless the caller supplies a different non-negative timeout;
- enforces a 512 MiB hard archive cap; callers may lower but never raise it;
- resolves the caller's staging directory to an absolute path and creates/protects it with the same private-directory helper used by update sequence state;
- creates a new exclusive temporary file with no overwrite of an existing path;
- writes the archive while calculating SHA-256, syncs it, and returns only after the digest exactly matches `manifest.installer_sha256`; and
- removes partial, oversized, short, or hash-mismatched staging files on failure.

The archive size limit is a resource bound, not an authenticity decision. Production manifests remain authoritative for the exact expected hash.

## Local staging is not permanent trust

A successful stage proves only that the bytes at the returned path matched the signed manifest at the end of the staging call. The path remains local mutable state.

`updateinfo.VerifyStagedInstaller` exists for the next trust boundary. It rejects symlinks, non-regular files, invalid size, replacement between path inspection and open, and any SHA-256 mismatch. A future installer-application path must invoke this re-verifier immediately before package/Authenticode validation and must not treat an earlier successful stage as sufficient.

The later application slice must additionally enforce the existing public-download policy:

- exact installer ZIP shape and internal checksum manifests;
- approved WeDecent Authenticode publisher, certificate-chain and timestamp policy for all five executables and three PowerShell installer scripts;
- fail-closed installer preflight;
- process ownership / restart semantics; and
- anti-rollback sequence commit only after installation is known to have succeeded.

The staging helper intentionally does not launch PowerShell, extract or execute ZIP contents, mutate installed files, or advance `update-state.json`.

## Cleanup and ownership

The returned `StagedInstaller.Path` belongs to the caller. The caller must remove it after success, cancellation, or abandonment. The staging helper removes only files from failed staging attempts because it cannot know the lifetime of a successfully returned archive.

No credentials, private keys, terminal data, manifest signing keys, or Authenticode secrets are written into the staged archive metadata.
