# Public Windows downloads

WeDecent release binaries intended for users must be downloadable without GitHub repository access. The public Windows release origin is:

```text
https://downloads.wedecent.com
```

The origin is backed by the Cloudflare R2 bucket `wedecent-downloads` through an R2 custom domain. Keep the R2 public development (`r2.dev`) URL disabled.

## Immutable URL layout

Every new published version uses one immutable prefix with separate release and installer archives:

```text
/windows/<version>/wedecent-<version>-windows-amd64.zip
/windows/<version>/SHA256SUMS.txt
/windows/<version>/wedecent-<version>-windows-installer.zip
/windows/<version>/INSTALLER_SHA256SUMS.txt
```

The release ZIP is the seven-file binary release payload. The installer ZIP is the production install/upgrade package, including the four signed PowerShell installer/update scripts, README, and complete package manifest. Each public checksum file contains exactly one entry for the archive beside it.

Never overwrite an object under a published version prefix. If release bytes need to change, publish a new version or release-candidate tag. Versioned download objects may be cached for a long time, so mutating an existing key can leave different users seeing different bytes.

There is deliberately no mutable `/windows/latest/` updater alias. The installed updater requires an explicit immutable target version. Version recommendation/discovery is outside the update trust boundary; immutable versioned URLs remain canonical.

## RC3 reference

`v0.3.0-rc.3` was published before the signed-publication pipeline described below. Its historical reference hashes are retained for auditability:

```text
ZIP SHA-256:
6e401b8666af3eee3666445e0d2ad685d0e68c6a80d648f47408f164fa8ef15d

wd.exe SHA-256:
996a84ee42e176e9382f58b53672141543ec79db1436b764b43a05407e2d6595

wd-agent.exe SHA-256:
165c94d215d69827315e31540aa974bc68c9e9c7defb13eea8878bc47e07100c
```

The public RC3 ZIP was downloaded from `downloads.wedecent.com` on an unauthenticated Windows machine and matched the expected ZIP SHA-256. It predates the public installer archive and must not be treated as the production signing/publication policy for new releases.

## Signed inputs

Complete the reproducible unsigned build, installer package, and Authenticode finalization documented in `docs/WINDOWS_RELEASE.md` before public publication.

The finalized signed release directory contains exactly:

```text
wd.exe
wd-agent.exe
wd-routerctl.exe
wd-core.exe
wd-ui.exe
VERSION.txt
SHA256SUMS.txt
```

The finalized signed installer directory contains exactly:

```text
wd.exe
wd-agent.exe
wd-routerctl.exe
wd-core.exe
wd-ui.exe
VERSION.txt
SHA256SUMS.txt
Install-WeDecent.ps1
Uninstall-WeDecent.ps1
Test-WeDecentInstall.ps1
Update-WeDecent.ps1
README.md
PACKAGE_SHA256SUMS.txt
```

The installer preparer requires the seven release files inside the installer tree to be byte-for-byte identical to the finalized signed release. `SHA256SUMS.txt` must be the canonical five-binary manifest. `PACKAGE_SHA256SUMS.txt` must be the canonical twelve-entry manifest for every installer-package payload file except the manifest itself. The production `WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER` must accept all five executables and all four PowerShell scripts before a public installer archive is trusted.

## Preparing canonical public archives

The release-only preparer remains available for inspection:

```bash
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER=/absolute/path/to/verifier \
  scripts/prepare-windows-public-download.sh \
    --version v0.4.0 \
    --signed-release dist/wedecent-windows-signed/release \
    --out-dir dist/wedecent-v0.4.0-release-public
```

Prepare the production installer archive with both finalized signed trees:

```bash
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER=/absolute/path/to/verifier \
  scripts/prepare-windows-public-installer.sh \
    --version v0.4.0 \
    --signed-release dist/wedecent-windows-signed/release \
    --signed-installer dist/wedecent-windows-signed/installer \
    --out-dir dist/wedecent-v0.4.0-installer-public
```

Both preparers snapshot their trusted inputs into private temporary trees before final checksum/signature verification and archive construction. The release ZIP has exactly seven files. The installer ZIP has exactly thirteen files. Both ZIPs use fixed file order and metadata, so identical signed inputs produce identical archive bytes. Existing output directories are never overwritten.

These preparation commands are useful for inspection, but the network publisher does not trust caller-supplied ZIPs. It repeats both preparation steps internally from the signed release and installer trees.

## Atomic create-only uploader

A preflight HTTP check is not sufficient to guarantee immutable publication: another publisher could create the same version key after the check but before an unconditional upload. Therefore the publication script never performs an unconditional object write.

When any public object is missing, configure:

```text
WEDECENT_R2_CREATE_ONLY_UPLOADER=/absolute/path/to/create-only-uploader
```

The path must be an absolute, regular, executable, non-symlink file. The publisher invokes it as:

```text
uploader BUCKET KEY FILE CONTENT_TYPE CONTENT_DISPOSITION CACHE_CONTROL
```

The uploader is an operator-owned credential boundary. It **must** perform an atomic create-only write and return nonzero if `KEY` already exists. For Cloudflare R2, use a conditional PutObject equivalent to `If-None-Match: *`. Do not implement the hook as a separate existence check followed by an unconditional put; that recreates the race this boundary closes.

The repository does not store R2 credentials or API tokens, and the publisher never passes them as command-line arguments. The uploader may use an organization-approved secret store, workload identity, or authenticated profile, but should have only the permissions needed to create release objects. There is deliberately no unconditional Wrangler fallback.

## Publishing

`scripts/publish-windows-downloads.sh` requires both finalized signed trees, constructs both canonical archives itself, then resolves the state of all four public objects before the first possible write. There is no `--archive` bypass.

```bash
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER=/absolute/path/to/verifier \
WEDECENT_R2_CREATE_ONLY_UPLOADER=/absolute/path/to/create-only-uploader \
  scripts/publish-windows-downloads.sh \
    --version v0.4.0 \
    --signed-release dist/wedecent-windows-signed/release \
    --signed-installer dist/wedecent-windows-signed/installer
```

Preview without uploading:

```bash
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER=/absolute/path/to/verifier \
  scripts/publish-windows-downloads.sh \
    --version v0.4.0 \
    --signed-release dist/wedecent-windows-signed/release \
    --signed-installer dist/wedecent-windows-signed/installer \
    --dry-run
```

A dry run still validates both signed trees, builds both canonical archives, and probes all four remote object states. Invalid signatures, checksum/package-manifest mismatches, release/installer byte mismatches, version mismatches, or unexpected files fail before a network request. HTTP 200 means an object is present and its exact bytes are verified; HTTP 404 means missing. Transport errors or any other HTTP status are ambiguous and fail closed rather than being treated as absence.

If a public object already exists with identical bytes, it is skipped. If an existing object differs, publication aborts. If any object is missing, the create-only uploader is required; any uploader failure aborts immediately. A concurrent publisher that wins a create race therefore causes the losing create-only operation to fail instead of overwriting the winning object. After all necessary creates, the publisher downloads and verifies all four public objects again.

The four-object publication is intentionally rerunnable rather than transactional across R2 keys. A process failure after one successful create may leave a subset of immutable objects present; rerunning with identical signed inputs verifies those existing bytes and safely creates only the missing objects.

## Verification

Verify the release archive without Cloudflare or GitHub credentials:

```bash
scripts/verify-public-windows-download.sh --version v0.4.0
```

Verify the production installer package:

```bash
scripts/verify-public-windows-download.sh --version v0.4.0 --installer
```

Release mode requires the exact seven-file archive, matching `VERSION.txt`, and a valid five-binary `SHA256SUMS.txt`. Installer mode requires the exact thirteen-file package, matching `VERSION.txt`, the same valid five-binary release manifest, and a valid `PACKAGE_SHA256SUMS.txt` covering all twelve package payload files.

For independent publisher authentication, provide the same external Authenticode policy verifier used by the release pipeline:

```bash
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER=/absolute/path/to/verifier \
  scripts/verify-public-windows-download.sh --version v0.4.0 --installer
```

The verifier path must be an absolute non-symlink executable. Release mode verifies all five extracted executables. Installer mode verifies those five executables plus all four PowerShell scripts. The adapter is responsible for enforcing the expected WeDecent publisher identity, certificate chain, signature validity, and timestamp policy.

SHA-256 checksums provide integrity for the exact public bytes but are not an independent authenticity proof when the checksum is served from the same origin. Use Authenticode-verifier mode when independent publisher authentication is required.

## Installed updater consumption

A signed installer places `Update-WeDecent.ps1` in the trusted Program Files installation. The updater consumes the same immutable installer archive and `INSTALLER_SHA256SUMS.txt` described above for an explicitly requested newer version. It independently enforces the outer checksum, exact thirteen-file archive shape, both internal manifests, requested version, and Authenticode signer continuity before invoking the transactional installer.

The updater does not trust an unsigned/mutable discovery pointer. It requires all target signed artifacts to use the same signer-certificate thumbprint as the currently installed signed updater and agent. See `docs/WINDOWS_UPDATE.md` for the detailed protocol and signer-rollover policy.

## Cloudflare configuration

The R2 bucket is:

```text
wedecent-downloads
```

The production custom domain is:

```text
downloads.wedecent.com
```

Keep the public development URL disabled. The custom domain is the supported public origin so Cloudflare cache, WAF, and related controls can apply.

Both ZIP objects should use:

```text
Content-Type: application/zip
Content-Disposition: attachment; filename="<archive-name>"
Cache-Control: public, max-age=31536000, immutable
```

Both checksum objects should use:

```text
Content-Type: text/plain; charset=utf-8
Cache-Control: public, max-age=31536000, immutable
```

Because published version keys are immutable, long-lived caching is safe. If an object must ever be withdrawn for security reasons, remove it from R2 and explicitly purge the Cloudflare cache for that URL.
