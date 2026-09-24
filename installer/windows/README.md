# WeDecent Windows installer foundation

This package carries the reproducible Windows release binaries and the PowerShell installer/update scripts without introducing a third-party installer runtime. Run installation commands from an elevated 64-bit Windows PowerShell session.

The installed program directory contains:

```text
wd.exe
wd-agent.exe
wd-routerctl.exe
wd-core.exe
wd-ui.exe
Update-WeDecent.ps1
```

`SHA256SUMS.txt` covers all five release binaries. `PACKAGE_SHA256SUMS.txt` covers the complete installer-package payload, including `Update-WeDecent.ps1`. `Install-WeDecent.ps1` now requires the complete installer package, verifies both manifests before mutation, pins the five binary hashes plus the updater hash, rechecks each source immediately before replacement, and verifies every installed copy before completing installation or restarting the service. The updater participates in the same `.new`/`.bak` rollback transaction as the executables.

Only `wd-agent.exe` is registered with the Windows Service Control Manager. The installer does not register `wd-core.exe` or `wd-ui.exe` as services, startup tasks, Run-key entries, or other automatic startup mechanisms. `wd-ui.exe` remains a same-user application; when it starts and the protected Local Core transport is absent, or when a later UI request observes transport-only Core loss, the UI may launch only the exact sibling `wd-core.exe` as that same user. `wd-routerctl.exe` is installed as a manual administrative utility and gains no service privilege merely by being present in Program Files.

After installation, an interactive user may explicitly opt their own `wd-ui.exe` into logon startup:

```powershell
& 'C:\Program Files\WeDecent\wd-ui.exe' autostart enable
& 'C:\Program Files\WeDecent\wd-ui.exe' autostart status
& 'C:\Program Files\WeDecent\wd-ui.exe' autostart disable
```

This current-user setting is owned by `wd-ui`, not by the elevated installer. Only `wd-ui.exe` is registered; Core remains bootstrapped by the UI in the same user context. The detailed ownership and uninstall semantics are documented in `docs/WINDOWS_UI_AUTOSTART.md`.

## Security properties

- Both `SHA256SUMS.txt` and the complete `PACKAGE_SHA256SUMS.txt` are verified before installation.
- Every installed binary and `Update-WeDecent.ps1` are checksum-verified after copy and before the installation transaction is committed.
- Fresh installs create a dedicated standard local account named `WeDecentSvc` by default.
- The service-account password is cryptographically random and is never written to disk, an environment variable, or a process command line. It is sent to `wd-agent.exe service install --account-password-stdin` through an inherited anonymous pipe.
- The installer rejects service accounts that are members of the local Administrators group and grants `SeServiceLogonRight` when needed.
- `wd-agent.exe` performs the existing identity initialization, state-directory ACL restriction, SCM registration, and service startup.
- Before any install/upgrade mutation, the installer checks for running installed `wd-ui.exe` and `wd-core.exe` images. If either is active, it fails before stopping the agent service or replacing files and instructs the operator to close the user processes. It never terminates those interactive processes itself.
- Upgrades stop the existing agent service only after that preflight succeeds, replace the verified installed-file set as one rollback unit, preserve identity/state/account configuration, and restore prior files if the upgraded service does not restart.
- Rollback tracks whether each destination existed before the transaction so a pre-copy failure cannot delete an untouched older file.
- Installer metadata is written atomically with an Administrators/SYSTEM-only ACL before it can authorize managed-account deletion.
- Normal uninstall removes the installed program directory, including the updater, while preserving cryptographic agent state and the service account. Permanent identity deletion requires explicit purge flags; `-WhatIf` is a real dry run.
- The elevated installer and uninstaller do not guess which interactive user's HKCU hive should own startup state. UI autostart is explicit, per-user, and managed by `wd-ui.exe` itself.

The process preflight compares the running image path with the exact installed `wd-ui.exe`/`wd-core.exe` destinations. A matching process whose executable path cannot be inspected is treated conservatively as a conflict. Close the installed UI/Core processes and rerun the installer. This prevents an autostarted UI from relaunching Core after the upgrade has already disrupted the agent service, and avoids depending on a later file-lock failure to trigger rollback.

Before uninstalling, a user who enabled UI autostart should run `wd-ui.exe autostart disable` in that same user context. The elevated uninstaller intentionally does not enumerate arbitrary users' HKCU Run entries; uninstalling without disabling may leave a harmless stale per-user startup value pointing to the removed image.

## Signed production packages

The ordinary release/package build remains unsigned so reproducibility can be checked before signatures introduce certificate and timestamp data. Production signing is performed afterward with `scripts/finalize-windows-signed-artifacts.sh`.

The finalizer requires two absolute executable hooks supplied by the release environment:

```text
WEDECENT_WINDOWS_AUTHENTICODE_SIGNER
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER
```

The signer receives exactly one absolute artifact path and must sign that file in place. The verifier receives exactly one absolute artifact path and must return success only for an Authenticode signature acceptable under the release policy. The finalizer never evaluates a shell command string, searches `PATH`, stores certificate material, or passes signing credentials as command-line arguments. Certificate/HSM/key-vault access and timestamp configuration belong to the wrapper and release environment.

After building and verifying the unsigned inputs:

```bash
make verify-release-windows
make release-windows
make installer-windows
export WEDECENT_WINDOWS_AUTHENTICODE_SIGNER=/absolute/path/to/wedecent-sign-wrapper
export WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER=/absolute/path/to/wedecent-verify-wrapper
make finalize-windows-signed
```

The finalizer signs the five executables and all four packaged PowerShell scripts (`Install`, `Uninstall`, `Test`, and `Update`) in a temporary copy, verifies every signed artifact, regenerates both checksum manifests from the signed bytes, and publishes only after all checks succeed. It does not mutate the unsigned release/package directories.

The default publishable tree is:

```text
dist/wedecent-windows-signed/
  release/
  installer/
```

Use the signed `installer/` payload for production distribution. The finalizer refuses to overwrite an existing signed output directory, so retries are explicit. Canonical CI uses fake signer/verifier fixtures only; it contains no production certificate or signing secret.

Do not weaken execution policy or Defender to run unsigned, invalidly signed, or untrusted packages.

## Install or upgrade from a package

```powershell
.\Install-WeDecent.ps1
.\Test-WeDecentInstall.ps1
```

`Install-WeDecent.ps1` expects the complete installer package. A release-only directory is no longer a valid installer input because it does not contain the package manifest or updater script.

Preview installer changes without mutating the machine:

```powershell
.\Install-WeDecent.ps1 -WhatIf
```

The same user-process preflight runs during `-WhatIf`, so a dry run can report that installed UI/Core processes must be closed without mutating the machine.

On a disposable fresh-install test machine, require proof that the service account was created and is installer-managed:

```powershell
.\Test-WeDecentInstall.ps1 -RequireManagedServiceAccount
```

The default paths are:

```text
C:\Program Files\WeDecent
C:\ProgramData\WeDecent\agent
```

On an already-installed host, running `Install-WeDecent.ps1` again performs an in-place verified-file upgrade and preserves the existing SCM configuration and machine identity.

If a local account named `WeDecentSvc` already exists but was not created by this installer, the installer refuses to take it over by default. Explicit adoption requires an in-memory `PSCredential`:

```powershell
$credential = Get-Credential '.\WeDecentSvc'
.\Install-WeDecent.ps1 -AdoptExistingServiceAccount -ServiceAccountCredential $credential
```

## Signed version-explicit update

After the first signed package containing the updater has been installed, subsequent upgrades can use the installed updater directly:

```powershell
& 'C:\Program Files\WeDecent\Update-WeDecent.ps1' -Version v0.4.1
```

The updater accepts only a specific immutable version path under `https://downloads.wedecent.com`. It rejects same-version installs and downgrades, does not use a mutable `latest` alias, does not follow HTTP redirects, and performs all download/extraction/verification in an elevated Program Files work directory. It validates the outer archive checksum, exact thirteen-file package shape, both internal checksum manifests, target version, and Authenticode on all five binaries plus all four scripts before invoking the existing transactional installer.

The installed updater and agent must already have valid Authenticode signatures from the same signer certificate, and every target signed artifact must use that exact certificate thumbprint. This deliberately blocks silent code-signing certificate rotation. Signer rollover requires an explicitly verified manual/out-of-band installer until a separately authenticated rollover protocol exists.

Close installed `wd-ui.exe` and `wd-core.exe` before running an update; the installer will fail before mutation rather than terminate them. See `docs/WINDOWS_UPDATE.md` for the complete trust model and first-updater-release migration note.

## Uninstall

If UI autostart was enabled for the current user, disable it before removing the installed image:

```powershell
& 'C:\Program Files\WeDecent\wd-ui.exe' autostart disable
```

Preserve device identity and account:

```powershell
.\Uninstall-WeDecent.ps1
```

Delete device state but retain the local account:

```powershell
.\Uninstall-WeDecent.ps1 -Purge
```

Delete state and an account that installer metadata proves was installer-managed:

```powershell
.\Uninstall-WeDecent.ps1 -Purge -RemoveServiceAccount
```

Never use the purge form for a normal upgrade or temporary uninstall. Deleting the state directory destroys the agent's device identity and requires re-enrollment/re-pairing.

## Silent use

A default fresh install is non-interactive: the installer generates the dedicated account password internally. An upgrade is also non-interactive when no installed UI/Core process is active. A running installed user-side process is an intentional fail-fast condition rather than something a silent installer kills automatically. Pre-existing unmanaged accounts require an explicit credential and are intentionally not silently reset.

The installer does not silently opt an interactive user into UI autostart. That choice must be made from the target user's context with `wd-ui.exe autostart enable`.

## Account enrollment before relay pairing

A newly created agent identity must be enrolled in the WeDecent account before relay pairing can obtain a connection grant. Use the challenge/proof bridge documented in `docs/WINDOWS_INSTALLER.md`: the authenticated `wd` client requests/completes the challenge, while `wd-agent enrollment-proof` signs it on the agent machine. The account session stays on the client and the agent private key stays on the agent.
