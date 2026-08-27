# Windows release hardening

The Windows release bundle is produced by `scripts/build-windows-release.sh` and is intentionally built without embedded VCS metadata from the Go toolchain. Release identity is injected through `internal/buildinfo` from controlled inputs instead.

## Version metadata

`VERSION` is the product version source. `wd version` and `wd-agent version` print the product version, Git commit, reproducible build timestamp, Go toolchain version, and target platform.

The release builder derives `built_at` from `SOURCE_DATE_EPOCH`. When that variable is unset, it uses the Git commit timestamp. A clean checkout of the same commit with the same Go toolchain therefore receives the same metadata. The builder uses `-trimpath`, `-buildvcs=false`, `CGO_ENABLED=0`, and an empty Go linker build ID.

Release builds refuse a dirty working tree. `WEDECENT_ALLOW_DIRTY=1` exists only for local diagnostic builds and marks the embedded commit with `-dirty`; dirty builds must not be published.

## Output

The default output directory is `dist/wedecent-windows-amd64/` and contains:

- `wd.exe`
- `wd-agent.exe`
- `VERSION.txt`
- `SHA256SUMS.txt`

`SHA256SUMS.txt` is generated from the exact executable bytes in the bundle.

## Reproducibility check

Run `scripts/verify-windows-release-repro.sh`. It builds the bundle twice with the same `SOURCE_DATE_EPOCH` and requires byte-identical executables, version metadata, and checksum manifests.

Reproducibility assumes the same Go toolchain version and target architecture. CI pins Go 1.27.0.

## Authenticode signing

The repository does not contain a code-signing private key or certificate. Production signing should use a protected CI signing identity, hardware-backed certificate, or external signing service. Never store a PFX password, private key, or signing certificate secret in Git.

The signing order is:

1. Build the clean release bundle.
2. Sign `wd.exe` and `wd-agent.exe` with SHA-256 Authenticode and an RFC 3161 timestamp service approved for the signing environment.
3. Verify each Authenticode signature on Windows.
4. Run `scripts/refresh-windows-release-checksums.sh` **after signing** so the manifest covers the exact signed bytes distributed to users.
5. Scan the final signed binaries with Microsoft Defender and any other release malware-scanning service. Do not infer safety from scans of component or pre-signing builds.

Example signing shape (certificate/provider details intentionally omitted):

```powershell
signtool sign /fd SHA256 /td SHA256 /tr <RFC3161_TIMESTAMP_URL> <SIGNING_IDENTITY_OPTIONS> wd.exe
signtool sign /fd SHA256 /td SHA256 /tr <RFC3161_TIMESTAMP_URL> <SIGNING_IDENTITY_OPTIONS> wd-agent.exe
signtool verify /pa /all /v wd.exe
signtool verify /pa /all /v wd-agent.exe
```

The final checksum manifest must be regenerated after these commands because Authenticode modifies the PE files.
