# Windows release hardening

The Windows release bundle is produced by `scripts/build-windows-release.sh` and is intentionally built without embedded VCS metadata from the Go toolchain. Release identity is injected through `internal/buildinfo` from controlled inputs instead.

## Version metadata

`VERSION` is the product version source. The Windows binaries expose the product version, Git commit, reproducible build timestamp, Go toolchain version, and target platform through their existing `version` commands.

The release builder derives `built_at` from `SOURCE_DATE_EPOCH`. When that variable is unset, it uses the Git commit timestamp. A clean checkout of the same commit with the same Go toolchain therefore receives the same metadata. The builder uses `-trimpath`, `-buildvcs=false`, `CGO_ENABLED=0`, and an empty Go linker build ID.

Release builds refuse a dirty working tree. `WEDECENT_ALLOW_DIRTY=1` exists only for local diagnostic builds and marks the embedded commit with `-dirty`; dirty builds must not be published.

## Unsigned reproducible output

The default unsigned output directory is `dist/wedecent-windows-amd64/` and contains:

- `wd.exe`
- `wd-agent.exe`
- `wd-routerctl.exe`
- `wd-core.exe`
- `wd-ui.exe`
- `VERSION.txt`
- `SHA256SUMS.txt`

`SHA256SUMS.txt` covers all five executable files. `scripts/refresh-windows-release-checksums.sh` also refreshes all five entries and fails if any expected binary is missing or not a regular non-symlink file.

Run `scripts/verify-windows-release-repro.sh` before signing. It builds the unsigned bundle twice with the same `SOURCE_DATE_EPOCH` and requires byte-identical executables, version metadata, and checksum manifests. Reproducibility assumes the same Go toolchain version and target architecture; CI pins Go 1.27.0.

Build the installer payload from that same unsigned release with `scripts/build-windows-installer-package.sh` (or `make installer-windows`). The installer package contains the same five executable bytes plus the PowerShell installer scripts and its outer `PACKAGE_SHA256SUMS.txt`.

## Authenticode finalization

The repository does not contain a code-signing private key, certificate secret, PFX password, or provider credential. Production signing should use a protected CI signing identity, hardware-backed certificate, or external signing service.

After the unsigned reproducibility check and installer-package build pass, finalize signed artifacts with:

```bash
WEDECENT_WINDOWS_AUTHENTICODE_SIGNER=/absolute/path/to/signer \
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER=/absolute/path/to/verifier \
make finalize-windows-signed
```

The signer and verifier are operator-supplied executable adapters. They receive exactly one artifact path per invocation. Do not encode credentials into their path or commit provider-specific secrets to this repository.

The finalizer:

1. verifies the unsigned release/package file sets and their existing checksum manifests;
2. requires the package's release files to match the unsigned release byte-for-byte;
3. refuses artifacts that already satisfy the supplied signature verifier;
4. copies the unsigned inputs into a temporary tree without modifying the reproducible sources;
5. signs and verifies all five executable files;
6. regenerates signed `release/SHA256SUMS.txt` from those signed PE bytes;
7. copies that exact signed release payload into the installer package;
8. signs and verifies `Install-WeDecent.ps1`, `Uninstall-WeDecent.ps1`, and `Test-WeDecentInstall.ps1`;
9. regenerates the signed installer `PACKAGE_SHA256SUMS.txt`;
10. re-verifies every signed artifact and checksum before atomically publishing the completed output directory.

The default finalized output is:

```text
dist/wedecent-windows-signed/
  release/
  installer/
```

The finalizer refuses to overwrite an existing output tree. A signer/verifier failure discards the temporary signing tree and leaves both unsigned source trees unchanged.

The production verifier is the release-policy boundary. It must reject signatures that do not meet the project's expected Authenticode certificate chain, publisher identity, signature validity, and RFC 3161 timestamp policy. CI deliberately uses fake signer/verifier fixtures only to test pipeline ordering, failure atomicity, manifest refresh, and publication behavior; CI does not simulate certificate trust.

Real production signing should use SHA-256 Authenticode and an approved RFC 3161 timestamp service. Scan the final signed binaries with Microsoft Defender and any other release malware-scanning service after signing; do not infer safety from pre-signing scans.

## Publication boundary

Only finalized signed artifacts should be used to construct a public Windows download. The unsigned reproducible tree is a build-verification baseline, not a distribution source.

Checksums provide integrity for the exact signed bytes, but a checksum served from the same download origin is not an independent authenticity proof. Public-release tooling should preserve the Authenticode-verification boundary before upload, and the public download should remain immutable once published.
