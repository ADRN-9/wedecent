# Public Windows downloads

WeDecent source code may live in a private repository, but release binaries intended
for users must be downloadable without GitHub repository access.

The public Windows release origin is:

```text
https://downloads.wedecent.com
```

The origin is backed by the Cloudflare R2 bucket `wedecent-downloads` through an R2
custom domain. Keep the R2 public development (`r2.dev`) URL disabled.

## Immutable URL layout

Every published release uses a versioned, immutable prefix:

```text
/windows/<version>/wedecent-<version>-windows-amd64.zip
/windows/<version>/SHA256SUMS.txt
```

For example:

```text
https://downloads.wedecent.com/windows/v0.3.0-rc.3/wedecent-v0.3.0-rc.3-windows-amd64.zip
https://downloads.wedecent.com/windows/v0.3.0-rc.3/SHA256SUMS.txt
```

Never overwrite an object under a published version prefix. If release bytes need to
change, publish a new version or release-candidate tag. Versioned download objects may
be cached for a long time, so mutating an existing key can leave different users seeing
different bytes.

Do not publish a mutable `/windows/latest/` alias for release candidates. A stable
release may add an explicitly managed latest-version manifest later, but immutable
versioned URLs remain the canonical release locations.

## RC3 reference

`v0.3.0-rc.3` was published before the signed-publication pipeline described below. Its
historical reference hashes are retained for auditability:

```text
ZIP SHA-256:
6e401b8666af3eee3666445e0d2ad685d0e68c6a80d648f47408f164fa8ef15d

wd.exe SHA-256:
996a84ee42e176e9382f58b53672141543ec79db1436b764b43a05407e2d6595

wd-agent.exe SHA-256:
165c94d215d69827315e31540aa974bc68c9e9c7defb13eea8878bc47e07100c
```

The public RC3 ZIP was downloaded from `downloads.wedecent.com` on an unauthenticated
Windows machine and matched the expected ZIP SHA-256. Do not treat that historical RC
procedure as the production signing policy for new releases.

## Signed release prerequisite

New public Windows releases must originate from the finalized signed release tree, not
from an arbitrary pre-built ZIP. Complete the reproducible unsigned build, installer
package, and Authenticode finalization documented in `docs/WINDOWS_RELEASE.md` first.

The signed release directory must contain exactly:

```text
wd.exe
wd-agent.exe
wd-routerctl.exe
wd-core.exe
wd-ui.exe
VERSION.txt
SHA256SUMS.txt
```

`SHA256SUMS.txt` must be a canonical five-entry manifest for those executable files and
must validate all five bytes. The operator-supplied
`WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER` must accept all five binaries under the
production publisher/certificate-chain/timestamp policy before public archive creation
or any network publication check occurs.

## Preparing the canonical public ZIP

For inspection or a local publication rehearsal, build the canonical ZIP directly from
the signed release:

```bash
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER=/absolute/path/to/verifier \
  scripts/prepare-windows-public-download.sh \
    --version v0.4.0 \
    --signed-release dist/wedecent-windows-signed/release \
    --out-dir dist/wedecent-v0.4.0-public
```

The preparer verifies the exact file set, canonical signed-release checksum manifest,
requested version, and all five Authenticode-verifier results. It snapshots the signed
release into a private temporary tree, verifies that snapshot, then writes a
deterministic stored ZIP containing the seven signed-release files plus a public
`SHA256SUMS.txt` covering that ZIP. The signed release input is never modified, and an
existing output directory is never overwritten.

This preparation command is useful for inspection, but the network publisher does not
trust an externally supplied archive. It repeats the preparation internally from the
signed release tree.

## Atomic create-only uploader

A preflight HTTP check is not sufficient to guarantee immutable publication: another
publisher could create the same version key after the check but before an unconditional
upload. Therefore the publication script never performs an unconditional object write.

When an object is missing, configure:

```text
WEDECENT_R2_CREATE_ONLY_UPLOADER=/absolute/path/to/create-only-uploader
```

The path must be an absolute, regular, executable, non-symlink file. The publisher
invokes it as:

```text
uploader BUCKET KEY FILE CONTENT_TYPE CONTENT_DISPOSITION CACHE_CONTROL
```

The uploader is an operator-owned credential boundary. It **must** perform an atomic
create-only write and return nonzero if `KEY` already exists. For Cloudflare R2, use a
conditional PutObject equivalent to `If-None-Match: *`. Do not implement the hook as a
separate existence check followed by an unconditional put; that recreates the race this
boundary is intended to close.

The repository does not store R2 credentials or API tokens, and the publisher never
passes them as command-line arguments. The uploader may use an organization-approved
secret store, workload identity, or authenticated profile, but should have only the
permissions needed to create release objects. There is deliberately no unconditional
Wrangler fallback because `wrangler r2 object put` does not provide the create-only
condition required by this immutability contract.

## Publishing

`scripts/publish-windows-downloads.sh` accepts the signed release directory, invokes the
canonical preparation step itself, and only then checks or creates immutable public
objects. There is no `--archive` bypass.

Example:

```bash
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER=/absolute/path/to/verifier \
WEDECENT_R2_CREATE_ONLY_UPLOADER=/absolute/path/to/create-only-uploader \
  scripts/publish-windows-downloads.sh \
    --version v0.4.0 \
    --signed-release dist/wedecent-windows-signed/release
```

Preview without uploading:

```bash
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER=/absolute/path/to/verifier \
  scripts/publish-windows-downloads.sh \
    --version v0.4.0 \
    --signed-release dist/wedecent-windows-signed/release \
    --dry-run
```

A dry run still verifies the signed release, builds the canonical archive, and probes
remote object state. Invalid signatures, checksum mismatches, version mismatches, or
unexpected release files fail before a network request. HTTP 200 means an object is
present and its bytes are verified; HTTP 404 means missing. Transport errors or any
other HTTP status are ambiguous and fail closed rather than being treated as absence.

If a public object already exists with identical bytes, the uploader is not required and
is not invoked. If an existing object differs, publication aborts. If an object is
missing, the create-only uploader is required; any uploader failure aborts immediately.
A concurrent publisher that wins the create race therefore causes the losing create-only
operation to fail instead of overwriting the winning object. After creation, the script
downloads the public archive and checksum manifest again and verifies their exact bytes.

## Verification

Anyone can perform integrity and package-shape verification without Cloudflare or GitHub
credentials:

```bash
scripts/verify-public-windows-download.sh --version v0.4.0
```

The verifier downloads the public checksum manifest and ZIP exactly once each. It
requires the public manifest to contain exactly one entry for the expected versioned
archive, verifies the ZIP SHA-256, rejects duplicate/unexpected/path-bearing archive
members, requires exactly the seven signed-release files, checks `VERSION.txt`, and
verifies that the internal `SHA256SUMS.txt` contains exactly one correct SHA-256 entry
for each of the five Windows binaries.

For independent publisher authentication, supply the same kind of external Authenticode
policy verifier used by the release pipeline:

```bash
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER=/absolute/path/to/verifier \
  scripts/verify-public-windows-download.sh --version v0.4.0
```

When that variable is set, the path must be an absolute non-symlink executable and all
five extracted binaries must pass it. The verifier adapter is responsible for enforcing
the expected WeDecent publisher identity, certificate chain, signature validity, and
timestamp policy.

SHA-256 checksums provide integrity for the exact public bytes but are not an independent
authenticity proof when the checksum is served from the same origin. Use the
Authenticode-verifier mode when independent publisher authentication is required.

## Cloudflare configuration

The R2 bucket is:

```text
wedecent-downloads
```

The production custom domain is:

```text
downloads.wedecent.com
```

Keep the public development URL disabled. The custom domain is the supported public
origin so Cloudflare cache, WAF, and related controls can apply.

Release ZIP objects should use:

```text
Content-Type: application/zip
Content-Disposition: attachment; filename="<archive-name>"
Cache-Control: public, max-age=31536000, immutable
```

Checksum objects should use:

```text
Content-Type: text/plain; charset=utf-8
Cache-Control: public, max-age=31536000, immutable
```

Because published version keys are immutable, long-lived caching is safe. If an object
must ever be withdrawn for security reasons, remove it from R2 and explicitly purge the
Cloudflare cache for that URL.
