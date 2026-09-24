# Signed Windows updates

WeDecent's Windows update path is deliberately **version-explicit**. There is no mutable
`/windows/latest/` alias and the updater does not discover or choose a version on the
user's behalf. A release channel, administrator, or future signed metadata mechanism may
recommend a version separately; the updater accepts only an explicit immutable version
such as `v0.4.1`.

## Usage

A signed production installation places the updater beside the installed binaries:

```powershell
& 'C:\Program Files\WeDecent\Update-WeDecent.ps1' -Version v0.4.1
```

The target must be strictly newer than the installed version. Reinstalling the same
version and downgrading are intentionally not updater operations. Use an explicitly
verified installer package for those exceptional cases.

Close installed `wd-ui.exe` and `wd-core.exe` before updating. The transactional
installer still performs its existing fail-before-mutation process preflight and never
kills interactive user processes.

## Trust boundary

The updater must itself be the installed `Update-WeDecent.ps1` under the trusted
Program Files installation recorded in ACL-protected installer metadata. When elevation
is needed it launches that exact installed script through the exact System32 Windows
PowerShell path with UAC; it never elevates a downloaded script and never requests an
execution-policy bypass.

After elevation, the updater revalidates:

- trusted installer metadata ownership/ACLs and the recorded install path;
- a valid Authenticode signature on the installed updater;
- a valid Authenticode signature on the installed `wd-agent.exe`;
- an exact signer-certificate thumbprint match between those two installed artifacts;
- the installed agent version and trusted installer metadata version.

The installed signer thumbprint becomes the continuity anchor for that update. Every
five executable and all four PowerShell scripts in the target installer package must
have a valid Authenticode signature from that exact certificate.

This intentionally **does not** silently support certificate rotation. A certificate
rollover changes the trust anchor and therefore requires an explicitly verified
out-of-band/manual installer procedure (or a future separately authenticated rollover
protocol). Treating any valid code-signing certificate as equivalent would weaken the
continuity guarantee.

## Immutable download protocol

For target `VERSION`, the updater requests exactly:

```text
https://downloads.wedecent.com/windows/VERSION/INSTALLER_SHA256SUMS.txt
https://downloads.wedecent.com/windows/VERSION/wedecent-VERSION-windows-installer.zip
```

The HTTP client does not follow redirects. Responses must be HTTP 200 and are streamed
under strict size limits. `INSTALLER_SHA256SUMS.txt` must contain exactly one canonical
SHA-256 entry naming the requested archive, and the downloaded archive must match that
digest before extraction.

The archive must contain exactly thirteen top-level regular files:

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

Duplicate members, directories, path-bearing names, non-regular Unix ZIP entries,
unexpected files, and oversized compressed or extracted payloads are rejected. The
updater extracts manually instead of accepting archive paths as filesystem paths.

`VERSION.txt` must match the requested immutable version. `SHA256SUMS.txt` must contain
exactly the five executable hashes. `PACKAGE_SHA256SUMS.txt` must contain exactly the
twelve package-payload hashes (all installer files except the package manifest itself),
and every covered file is rehashed after extraction.

## Privileged handoff

All network download, archive extraction, checksum validation, Authenticode validation,
and installer execution happen in the elevated updater. Its temporary work directory is
created underneath the trusted Program Files installation rather than in a medium-
integrity user-writable temp directory. This avoids a user-writable verification-to-
execution handoff.

Only after the package has passed all checksum, version, archive-shape, and signer-
continuity checks does the updater launch the downloaded signed `Install-WeDecent.ps1`
with the trusted install directory, state directory, and service name from installer
metadata. It uses the exact System32 Windows PowerShell executable and does not weaken
PowerShell execution policy.

The existing installer remains authoritative for file replacement, service restart,
post-copy verification, and rollback. `Update-WeDecent.ps1` itself is one of the files
installed by that same rollback transaction, so successful upgrades advance the updater
with the rest of the installation.

## Release requirements

`Update-WeDecent.ps1` is part of the installer package, is covered by
`PACKAGE_SHA256SUMS.txt`, is Authenticode-signed by the Windows release finalizer, and is
verified by public-installer preparation and verification. It is intentionally **not**
part of the seven-file release-only ZIP.

The first release containing this updater must be installed once through the normal
signed installer path on machines running an older release that did not yet install
`Update-WeDecent.ps1`. Subsequent version-explicit updates can use the installed updater.
