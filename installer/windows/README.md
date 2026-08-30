# WeDecent Windows installer foundation

This package installs the reproducible `wd.exe` and `wd-agent.exe` release binaries without introducing a third-party installer runtime. Run the scripts from an elevated 64-bit Windows PowerShell session.

## Security properties

- `SHA256SUMS.txt` is verified before installation.
- Fresh installs create a dedicated standard local account named `WeDecentSvc` by default.
- The service-account password is cryptographically random and is never written to disk, an environment variable, or a process command line. It is sent to `wd-agent.exe service install --account-password-stdin` through an inherited anonymous pipe.
- The installer rejects service accounts that are members of the local Administrators group and grants `SeServiceLogonRight` when needed.
- `wd-agent.exe` performs the existing identity initialization, state-directory ACL restriction, SCM registration, and service startup.
- Upgrades stop the existing service, replace only the binaries, preserve identity/state/account configuration, and roll back the binaries if the upgraded service does not restart.
- Installer metadata is written atomically with an Administrators/SYSTEM-only ACL before it can authorize managed-account deletion.
- Normal uninstall preserves cryptographic agent state and the service account. Permanent identity deletion requires explicit purge flags; `-WhatIf` is a real dry run.

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

The PowerShell scripts themselves are not Authenticode-signed yet. Production packaging should sign the scripts and binaries before distribution; do not weaken execution policy or Defender to run an untrusted package.

## Account enrollment before relay pairing

A newly created agent identity must be enrolled in the WeDecent account before relay
pairing can obtain a connection grant. Use the challenge/proof bridge documented in
`docs/WINDOWS_INSTALLER.md`: the authenticated `wd` client requests/completes the
challenge, while `wd-agent enrollment-proof` signs it on the agent machine. The account
session stays on the client and the agent private key stays on the agent.
