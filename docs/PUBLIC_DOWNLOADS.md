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

`v0.3.0-rc.3` was published with:

```text
ZIP SHA-256:
6e401b8666af3eee3666445e0d2ad685d0e68c6a80d648f47408f164fa8ef15d

wd.exe SHA-256:
996a84ee42e176e9382f58b53672141543ec79db1436b764b43a05407e2d6595

wd-agent.exe SHA-256:
165c94d215d69827315e31540aa974bc68c9e9c7defb13eea8878bc47e07100c
```

The public RC3 ZIP was downloaded from `downloads.wedecent.com` on an unauthenticated
Windows machine and matched the expected ZIP SHA-256.

## Publishing

`scripts/publish-windows-downloads.sh` publishes an already-built ZIP. It does not
rebuild or modify release binaries.

The script validates the version and archive filename, computes the ZIP SHA-256,
generates the public checksum manifest, refuses to replace an existing public object
with different bytes, uploads missing objects with Wrangler, applies immutable cache
metadata, and verifies the public URL after upload.

Example:

```bash
scripts/publish-windows-downloads.sh   --version v0.3.0-rc.3   --archive /path/to/wedecent-v0.3.0-rc.3-windows-amd64.zip
```

Preview without uploading:

```bash
scripts/publish-windows-downloads.sh   --version v0.3.0-rc.3   --archive /path/to/wedecent-v0.3.0-rc.3-windows-amd64.zip   --dry-run
```

The publisher expects an authenticated `wrangler` executable when an upload is needed.
Do not pass Cloudflare credentials as command-line flags and do not store API tokens in
the repository. Use Wrangler's authenticated profile or secret-backed CI credentials
with only the permissions required to write release objects.

## Verification

Anyone can verify a published version without Cloudflare or GitHub credentials:

```bash
scripts/verify-public-windows-download.sh --version v0.3.0-rc.3
```

The verifier downloads the checksum manifest and hashes the public ZIP stream. A
successful result proves the bytes at the public URL match the public manifest.

SHA-256 checksums provide corruption/integrity detection; a checksum served from the
same origin is not an independent authenticity proof. Stable Windows distribution
should additionally use the project's code-signing/release-signing policy.

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
