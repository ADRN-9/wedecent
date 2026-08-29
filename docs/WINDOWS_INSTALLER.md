# Windows installer

The first v0.3 installer layer is a PowerShell package around the reproducible Windows release bundle. It intentionally does not introduce MSI/WiX yet; the goal is to prove secure install, upgrade, rollback, reboot persistence, and uninstall semantics before freezing an MSI authoring model.

`installer/windows/Install-WeDecent.ps1` verifies the release executable checksums, installs both binaries under `C:\Program Files\WeDecent`, creates a dedicated standard local service account when needed, grants `SeServiceLogonRight`, and delegates identity creation, ACL hardening, SCM registration, and runtime configuration to `wd-agent.exe service install`.

Service-account passwords are not accepted on the command line. Installer metadata is written atomically with a hardened Administrators/SYSTEM ACL and is treated as untrusted if that protection is missing. For automated installation the installer passes the password through standard input to the Windows-only `--account-password-stdin` service-install option. Existing interactive behavior remains the default when that flag is absent.

Upgrades preserve the existing service account, SCM arguments, and `C:\ProgramData\WeDecent\agent` state. Binary replacement has a local rollback copy and restores the previous binaries if the upgraded service cannot start.

Normal uninstall removes the service and program files but preserves the agent state and service account. Install and uninstall support a functional `-WhatIf` preflight; destructive paths are constrained to the WeDecent locations beneath Program Files and ProgramData and reparse-point traversal is rejected. `-Purge` explicitly removes the agent state. `-Purge -RemoveServiceAccount` additionally removes an account only when installer metadata proves that account was created/managed by this installer and its SID still matches.

Build the package after the release bundle:

```bash
make installer-windows
```

The package is written to `dist/wedecent-windows-installer/` and contains an outer `PACKAGE_SHA256SUMS.txt` in addition to the release bundle's executable `SHA256SUMS.txt`. The packaging script refuses output paths outside the repository `dist/` tree or paths that overlap the release input directory.

Production distribution still requires Authenticode signing of the final binaries and PowerShell scripts. Do not weaken Defender or PowerShell execution policy to compensate for unsigned or untrusted artifacts.
