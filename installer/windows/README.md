# WeDecent Windows installer foundation

This package carries the reproducible Windows release binaries and the installer scripts without introducing a third-party installer runtime. Run the installer scripts from an elevated 64-bit Windows PowerShell session.

The package and installed program directory contain:

```text
wd.exe
wd-agent.exe
wd-routerctl.exe
wd-core.exe
wd-ui.exe
```

`SHA256SUMS.txt` covers all five release binaries, and `PACKAGE_SHA256SUMS.txt` covers the complete installer-package payload. `Install-WeDecent.ps1` verifies the release hashes before mutation, pins those verified values, rechecks each source immediately before replacement, and verifies the installed copies against the pinned values before completing installation or restarting the service.

Only `wd-agent.exe` is registered with the Windows Service Control Manager. The installer does not register `wd-core.exe` or `wd-ui.exe` as services, startup tasks, Run-key entries, or other autostart mechanisms. `wd-ui.exe` remains an explicitly launched same-user application; when it starts and the protected Local Core transport is absent, the UI may launch only the exact sibling `wd-core.exe` as that same user. `wd-routerctl.exe` is installed as a manual administrative utility and gains no service privilege merely by being present in Program Files.

## Security properties

- `SHA256SUMS.txt` is verified before installation/package creation, and the installer package contains every binary referenced by that manifest.
- Every installed binary is checksum-verified after copy and before the installation transaction is committed.
- Fresh installs create a dedicated standard local account named `WeDecentSvc` by default.
- The service-account password is cryptographically random and is never written to disk, an environment variable, or a process command line. It is sent to `wd-agent.exe service install --account-password-stdin` through an inherited anonymous pipe.
- The installer rejects service accounts that are members of the local Administrators group and grants `SeServiceLogonRight` when needed.
- `wd-agent.exe` performs the existing identity initialization, state-directory ACL restriction, SCM registration, and service startup.
- Upgrades stop the existing agent service, replace the verified binary set as one rollback unit, preserve identity/state/account configuration, and restore prior binaries if the upgraded service does not restart.
- Rollback tracks whether each destination existed before the transaction so a pre-copy failure cannot delete an untouched older binary.
- Installer metadata is written atomically with an Administrators/SYSTEM-only ACL before it can authorize managed-account deletion.
- Normal uninstall removes the installed program directory, including all five binaries, while preserving cryptographic agent state and the service account. Permanent identity deletion requires explicit purge flags; `-WhatIf` is a real dry run.

If `wd-core.exe`, `wd-ui.exe`, or another installed executable is running and Windows refuses to replace its image during an upgrade, the installer fails the transaction rather than killing an interactive process or silently leaving mixed binary versions. Close the process and rerun the installer.

The package hash manifests provide integrity relative to the package contents; they are not a substitute for code signing. The PowerShell scripts and binaries are not Authenticode-signed yet, so production packaging should sign them before distribution. Do not weaken execution policy or Defender to run an untrusted package.

## Install or upgrade

```powershell
.\Install-WeDecent.ps1
.\Test-WeDecentInstall.ps1
```

Preview installer changes without mutating the machine:

```powershell
.\Install-WeDecent.ps1 -WhatIf
```

On a disposable fresh-install test machine, require proof that the service account was created and is installer-managed:

```powershell
.\Test-WeDecentInstall.ps1 -RequireManagedServiceAccount
```

The default paths are:

```text
C:\Program Files\WeDecent
C:\ProgramData\WeDecent\agent
```

On an already-installed host, running `Install-WeDecent.ps1` again performs an in-place binary upgrade and preserves the existing SCM configuration and machine identity.

If a local account named `WeDecentSvc` already exists but was not created by this installer, the installer refuses to take it over by default. Explicit adoption requires an in-memory `PSCredential`:

```powershell
$credential = Get-Credential '.\WeDecentSvc'
.\Install-WeDecent.ps1 -AdoptExistingServiceAccount -ServiceAccountCredential $credential
```

## Uninstall

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

A default fresh install is non-interactive: the installer generates the dedicated account password internally. An upgrade is also non-interactive. Pre-existing unmanaged accounts require an explicit credential and are intentionally not silently reset.

## Account enrollment before relay pairing

A newly created agent identity must be enrolled in the WeDecent account before relay
pairing can obtain a connection grant. Use the challenge/proof bridge documented in
`docs/WINDOWS_INSTALLER.md`: the authenticated `wd` client requests/completes the
challenge, while `wd-agent enrollment-proof` signs it on the agent machine. The account
session stays on the client and the agent private key stays on the agent.
