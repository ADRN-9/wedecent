# Windows release hardening

The Windows release bundle is produced by `scripts/build-windows-release.sh` and is intentionally built without embedded VCS metadata from the Go toolchain. Release identity is injected through `internal/buildinfo` from controlled inputs instead.

## Version metadata

`VERSION` is the product version source. The Windows binaries expose the product version, Git commit, reproducible build timestamp, Go toolchain version, and target platform through their existing `version` commands.

The release builder derives `built_at` from `SOURCE_DATE_EPOCH`. When that variable is unset, it uses the Git commit timestamp. A clean checkout of the same commit with the same Go toolchain therefore receives the same metadata. The builder uses `-trimpath`, `-buildvcs=false`, `CGO_ENABLED=0`, and an empty Go linker build ID.

Release builds refuse a dirty working tree. `WEDECENT_ALLOW_DIRTY=1` exists only for local diagnostic builds and marks the embedded commit with `-dirty`; dirty builds must not be published.

## Unsigned reproducible output

The default unsigned release directory is `dist/wedecent-windows-amd64/` and contains the five executables plus `VERSION.txt` and the five-entry `SHA256SUMS.txt`.

Run `scripts/verify-windows-release-repro.sh` before signing. It builds the unsigned bundle twice with the same `SOURCE_DATE_EPOCH` and requires byte-identical executables, version metadata, and checksum manifests. Reproducibility assumes the same Go toolchain version and target architecture; CI pins Go 1.27.0.

Build the installer payload from that same unsigned release with `scripts/build-windows-installer-package.sh` (or `make installer-windows`). The installer package contains the same five executable bytes plus:

```text
VERSION.txt
SHA256SUMS.txt
Install-WeDecent.ps1
Uninstall-WeDecent.ps1
Test-WeDecentInstall.ps1
Update-WeDecent.ps1
README.md
PACKAGE_SHA256SUMS.txt
```

The package manifest covers the twelve payload files other than `PACKAGE_SHA256SUMS.txt` itself. `Install-WeDecent.ps1` requires this complete package; release-only directories are not installer inputs.

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

1. verifies the unsigned release/package file sets and checksum manifests;
2. requires the package's release files to match the unsigned release byte-for-byte;
3. refuses artifacts that already satisfy the supplied signature verifier;
4. copies the unsigned inputs into a temporary tree without modifying the reproducible sources;
5. signs and verifies all five executable files;
6. regenerates signed `release/SHA256SUMS.txt` from those signed PE bytes;
7. copies that exact signed release payload into the installer package;
8. signs and verifies `Install-WeDecent.ps1`, `Uninstall-WeDecent.ps1`, `Test-WeDecentInstall.ps1`, and `Update-WeDecent.ps1`;
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

## Public-download preparation and publication

Only finalized signed artifacts may be used to construct new public Windows downloads. The unsigned reproducible trees are build-verification baselines, not distribution sources.

`scripts/prepare-windows-public-download.sh` consumes the finalized signed `release/` directory. It requires the production Authenticode verifier, checks the exact seven-file release shape, validates the canonical five-entry checksum manifest, snapshots the signed release into a private temporary tree, verifies all five executable signatures and checksums, checks that `VERSION.txt` matches the requested public version, and creates a deterministic release ZIP plus one-line public checksum manifest.

`scripts/prepare-windows-public-installer.sh` consumes both finalized signed trees. It requires the exact thirteen-file installer-package shape, requires every one of the seven release files inside `installer/` to match `release/` byte-for-byte, validates the canonical release and complete package manifests, verifies the five executable and four PowerShell Authenticode signatures, and creates a deterministic installer ZIP plus its separate one-line `INSTALLER_SHA256SUMS.txt`.

`scripts/publish-windows-downloads.sh` requires both the signed release and signed installer directories and does not accept caller-supplied archives. It invokes both preparation steps before any network request, then resolves all four immutable public object states before the first possible write. Existing public objects must match the prepared bytes exactly. Missing objects may be created only through the operator-supplied `WEDECENT_R2_CREATE_ONLY_UPLOADER`, whose contract requires an atomic create-only write and failure if the key already exists. There is no unconditional upload fallback.

The four-object publication is rerunnable rather than transactional across R2 keys. After a partial process failure, identical existing objects are verified and only missing objects are created on the next run.

The public verifier has two modes. Release mode validates the seven-file release archive and five-binary manifest. `--installer` mode validates the thirteen-file installer archive, its complete `PACKAGE_SHA256SUMS.txt`, and, when configured, Authenticode on all five binaries plus all four PowerShell scripts.

See `docs/PUBLIC_DOWNLOADS.md` for object layout, uploader contract, operator commands, and public verification. Checksums provide integrity for the exact signed bytes, but a checksum served from the same download origin is not an independent authenticity proof. Consumers with an authenticity requirement should also verify Authenticode against the expected WeDecent publisher policy.

## Version-explicit signed updates

A production installer now installs `Update-WeDecent.ps1` in the Program Files installation as part of the same checksum-pinned rollback transaction as the executables. The updater consumes only immutable versioned installer URLs and intentionally has no mutable `latest` alias.

For example:

```powershell
& 'C:\Program Files\WeDecent\Update-WeDecent.ps1' -Version v0.4.1
```

The updater requires a strictly newer target, validates the public archive checksum, exact thirteen-file archive/package shape, both internal manifests, target version, and Authenticode on all five binaries plus all four scripts. It also requires every target signature to use the exact signer-certificate thumbprint trusted by the currently installed signed updater and agent. Certificate rollover is therefore an explicit manual/out-of-band trust transition, not something the updater silently accepts.

Download, extraction, verification, and installer execution occur only after elevation in an Administrators-protected work directory under the installed Program Files tree. The updater does not follow HTTP redirects, elevate a downloaded script, use a user-writable privileged handoff, or request `-ExecutionPolicy Bypass`.

See `docs/WINDOWS_UPDATE.md` for the complete update protocol and first-release migration details.
