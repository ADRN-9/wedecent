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

Only `wd-agent.exe` is registered with the Windows Service Control Manager. The installer does not register `wd-core.exe` or `wd-ui.exe` as services, startup tasks, Run-key entries, or other automatic startup mechanisms. `wd-ui.exe` remains a same-user application; when it starts and the protected Local Core transport is absent, or when a later UI request observes transport-only Core loss, the UI may launch only the exact sibling `wd-core.exe` as that same user. `wd-routerctl.exe` is installed as a manual administrative utility and gains no service privilege merely by being present in Program Files.

After installation, an interactive user may explicitly opt their own `wd-ui.exe` into logon startup:

```powershell
& 'C:\Program Files\WeDecent\wd-ui.exe' autostart enable
& 'C:\Program Files\WeDecent\wd-ui.exe' autostart status
& 'C:\Program Files\WeDecent\wd-ui.exe' autostart disable
```

This current-user setting is owned by `wd-ui`, not by the elevated installer. Only `wd-ui.exe` is registered; Core remains bootstrapped by the UI in the same user context. The detailed ownership and uninstall semantics are documented in `docs/WINDOWS_UI_AUTOSTART.md`.

## Security properties

- `SHA256SUMS.txt` is verified before installation/package creation, and the installer package contains every binary referenced by that manifest.
- Every installed binary is checksum-verified after copy and before the installation transaction is committed.
- Fresh installs create a dedicated standard local account named `WeDecentSvc` by default.
- The service-account password is cryptographically random and is never written to disk, an environment variable, or a process command line. It is sent to `wd-agent.exe service install --account-password-stdin` through an inherited anonymous pipe.
- Fresh service state defaults to `C:\\Program Files\\WeDecent\\data\\agent`, beneath the protected Program Files hierarchy. The installer refuses state paths outside the selected installation directory; it does not fall back to ProgramData when ancestor ACL validation fails. Existing installations retain their recorded state path until an explicit identity-preserving migration has been completed.\n- Fresh service installation requires an origin-only HTTPS recovery-authority URL, its exact 64-hex SPKI pin, a protected public trust file, and a short-lived bearer. URL/pin may be supplied as non-secret parameters or environment configuration; the trust file is passed by path. The bearer is prompted as a `SecureString` (or supplied as one) and streamed after the account password through stdin; it is never placed in argv or environment variables. SecureString characters are copied through a zeroed character buffer and zeroed unmanaged allocation.
- The service installer copies the trust anchors and bearer into create-exclusive files in the protected service state directory, then validates their ACLs. The bearer file is plaintext at rest protected by the NTFS DACL; Local Administrators and LocalSystem remain trusted.
- Service-state provisioning also requires the immediate parent directory to have a protected owner/DACL owned by the installer, SYSTEM, Administrators, or TrustedInstaller. It refuses broad existing parents rather than changing ancestor ACLs. Windows permits the same directory owner to rename an open directory; the handle guard is not a substitute for the parent ACL. A same-identity rename makes the old pathname fail closed on subsequent verification.
- The installer rejects service accounts that are members of the local Administrators group and grants `SeServiceLogonRight` when needed.
- `wd-agent.exe` performs the existing identity initialization, state-directory ACL restriction, SCM registration, and service startup.
- Before any install/upgrade mutation, the installer checks for running installed `wd-ui.exe` and `wd-core.exe` images. If either is active, it fails before stopping the agent service or replacing files and instructs the operator to close the user processes. It never terminates those interactive processes itself.
- Upgrades stop the existing agent service only after that preflight succeeds, replace the verified binary set as one rollback unit, preserve identity/state/account configuration, and restore prior binaries if the upgraded service does not restart.
- Rollback tracks whether each destination existed before the transaction so a pre-copy failure cannot delete an untouched older binary.
- Installer metadata is written atomically with an Administrators/SYSTEM-only ACL before it can authorize managed-account deletion.
- Normal uninstall removes the installed program directory, including all five binaries, while preserving cryptographic agent state and the service account. Permanent identity deletion requires explicit purge flags; `-WhatIf` is a real dry run.
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

The finalizer signs the five executables and the three packaged PowerShell scripts in a temporary copy, verifies every signed artifact, regenerates both checksum manifests from the signed bytes, and publishes only after all checks succeed. It does not mutate the unsigned release/package directories.

The default publishable tree is:

```text
dist/wedecent-windows-signed/
  release/
  installer/
```

Use the signed `installer/` payload for production distribution. The finalizer refuses to overwrite an existing signed output directory, so retries are explicit. Canonical CI uses fake signer/verifier fixtures only; it contains no production certificate or signing secret.

Do not weaken execution policy or Defender to run unsigned, invalidly signed, or untrusted packages.

## Install or upgrade

Fresh installation requires recovery-authority provisioning. Stage the independently administered public trust JSON in a file whose ACL is restricted to the installer, SYSTEM and Administrators; supply the HTTPS origin and exact 64-hex leaf-SPKI SHA-256 pin. The bearer is prompted securely if not supplied as a `SecureString`.

```powershell
$env:WEDECENT_PAIRING_RECOVERY_AUTHORITY_URL = 'https://recovery.example.invalid'
$env:WEDECENT_PAIRING_RECOVERY_AUTHORITY_SPKI_SHA256 = '<64-hex-leaf-SPKI-pin>'
$recoveryBearer = Read-Host 'Short-lived recovery-authority bearer token' -AsSecureString
.\Install-WeDecent.ps1 -RecoveryAuthorityTrustFile 'C:\ProgramData\WeDecent\recovery-authority-trust.json' -RecoveryAuthorityBearerToken $recoveryBearer
.\Test-WeDecentInstall.ps1
```

The trust file must be a valid primary/witness public trust document and pass the repository's protected-file ACL check. Never put the bearer in a command-line argument or environment variable. The installer streams the account password first and bearer second through the child process's inherited stdin pipe.

```powershell
.\Install-WeDecent.ps1
.\Test-WeDecentInstall.ps1
```

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
C:\Program Files\WeDecent\data\agent
```

`C:\ProgramData\WeDecent\agent` is the legacy state location used by older installations; it is not the current fresh-install default. Existing installations keep their authenticated recorded `state_dir` and must not be redirected to Program Files until the identity-preserving migration described below is implemented and accepted. The installer currently refuses a legacy ProgramData state directory on a fresh install rather than creating a replacement identity, and refuses an upgrade that changes the recorded state path. Automated migration, crash recovery, and privileged rollback acceptance remain unimplemented.

On an already-installed host, running `Install-WeDecent.ps1` again performs an in-place binary upgrade and preserves the existing SCM configuration and machine identity only when the authenticated recorded state path is unchanged.

If a local account named `WeDecentSvc` already exists but was not created by this installer, the installer refuses to take it over by default. Explicit adoption requires an in-memory `PSCredential`:

```powershell
$credential = Get-Credential '.\WeDecentSvc'
.\Install-WeDecent.ps1 -AdoptExistingServiceAccount -ServiceAccountCredential $credential
```

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

A default fresh install prompts securely for the short-lived recovery bearer unless a `SecureString` is supplied programmatically; the installer generates the dedicated account password internally. An upgrade is non-interactive when no installed UI/Core process is active. A running installed user-side process is an intentional fail-fast condition rather than something a silent installer kills automatically. Pre-existing unmanaged accounts require an explicit credential and are intentionally not silently reset.

The installer does not silently opt an interactive user into UI autostart. That choice must be made from the target user's context with `wd-ui.exe autostart enable`.

## Account enrollment before relay pairing

A newly created agent identity must be enrolled in the WeDecent account before relay
pairing can obtain a connection grant. Use the challenge/proof bridge documented in
`docs/WINDOWS_INSTALLER.md`: the authenticated `wd` client requests/completes the
challenge, while `wd-agent enrollment-proof` signs it on the agent machine. The account
session stays on the client and the agent private key stays on the agent.


If a fresh installation is interrupted after the service installer has created recovery files or identity state, rollback removes only an empty newly created state directory. It preserves non-empty protected state and reports that explicit offline recovery/re-enrollment is required; it never recursively deletes newly created identity, trust, audit or pairing material.


## Windows service-state location and migration

Fresh installations use:

```text
%ProgramFiles%\WeDecent\data\agent
```

The state directory is created with a protected DACL and then assigned to the dedicated service account. The complete ancestor chain remains subject to the same owner and ACL validation used at service startup. ProgramData is not a fallback: if the Program Files hierarchy does not pass strict validation, installation must fail.

Existing installations must not be silently redirected to the new default. The installer metadata records the existing `state_dir`; upgrade logic must preserve that recorded location until a migration is explicitly executed. A migration must stop the service, validate source ownership and ACLs (including a narrowly documented ProgramData ancestor exception only where no principal can delete, replace, take ownership of, or change the DACL of the protected child), copy the complete state tree to a protected staging sibling on the destination volume, verify every copied file byte-for-byte and by SHA-256, verify identity certificate/public-key correspondence and trust/recovery material, then atomically rename staging to a previously absent destination. The source remains untouched as rollback evidence until the service has restarted from the destination and its device fingerprint is confirmed unchanged. Service configuration is switched only after destination verification; any interrupted stage or failed restart restores the original service binary path and leaves both state trees intact. No recursive overwrite or identity regeneration is permitted.

**Migration status:** automated migration and its privileged rollback acceptance are not yet implemented. Existing installations requiring relocation must not be upgraded by changing only the state path. The operator must retain the old state and service account until the migration tool and privileged Windows acceptance are available.
