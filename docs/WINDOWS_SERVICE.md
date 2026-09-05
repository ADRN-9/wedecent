# Windows service mode

The v0.3 Windows agent includes native Windows Service Control Manager (SCM) integration without adding third-party Go dependencies.

## Security model

The service deliberately refuses the built-in `LocalSystem`, `LocalService`, and `NetworkService` identities. Install it under a dedicated standard Windows account whose permissions match the shell access you intend to expose.

Relay-auth-v2 streams use short-lived Ed25519 tickets signed by the machine identity, so `wd-agent service install` no longer requires or stores a shared relay token. The state directory ACL is restricted to:

- the configured service account;
- LocalSystem;
- local Administrators.

The service identity private key in this directory now supplies relay proof-of-possession. Do not loosen the state-directory ACL.

## Prerequisites

1. Build or install `wd-agent.exe` at its final permanent path. The SCM records that executable path during installation.
2. Create a dedicated standard Windows account, for example `WeDecentSvc`.
3. Grant that account the Windows **Log on as a service** user right.
4. Run the install command from an elevated PowerShell window.

Do not install the service under your normal administrator account or a built-in service identity.

## Install

Example from elevated PowerShell:

```powershell
cd C:\Program Files\WeDecent

.\wd-agent.exe service install `
  --account ".\\WeDecentSvc" `
  --listen= `
  --web-relay=https://relay.wedecent.com `
  --relay-slots=4
```

The installer prompts without echo only for the service-account password (unless a passwordless managed service identity is used).

It then:

- creates/loads the machine-wide device identity;
- creates a new one-time pairing secret;
- locks down the state directory ACL;
- registers the Windows service;
- starts the service unless `--start=false` is supplied.

The default machine-wide state directory is:

```text
C:\ProgramData\WeDecent\agent
```

The service log is:

```text
C:\ProgramData\WeDecent\agent\service.log
```

Keep the printed pairing secret private. It is single-use.

## Manage

```powershell
.\wd-agent.exe service status
.\wd-agent.exe service stop
.\wd-agent.exe service start
.\wd-agent.exe service uninstall
```

Use a non-default service name consistently with `--service-name` on management commands.

## Upgrade from the v4 service prototype

The earlier service prototype stored `relay-token.dpapi` in the state directory. Relay-auth-v2 does not read that file. After the Worker is on v5 and the upgraded service has been validated, the stale DPAPI blob can be removed from the machine.

## Service runtime

The SCM starts the binary with the internal command:

```text
wd-agent.exe service run ...
```

Do not invoke `service run` manually. It connects to the Windows SCM, reports start/running/stop states, and translates SCM stop/shutdown requests into context cancellation for the normal WeDecent agent runtime.

The existing interactive command also uses relay-auth-v2 and needs no relay secret:

```powershell
.\wd-agent.exe serve --listen= --web-relay=https://relay.wedecent.com --relay-slots=4
```

The upgraded service does not read `WEDECENT_RELAY_TOKEN`.

## Package installer

The release package now includes `Install-WeDecent.ps1`, `Uninstall-WeDecent.ps1`, and `Test-WeDecentInstall.ps1`. The package installer creates the dedicated local account on a fresh machine, grants **Log on as a service**, verifies release checksums, and delegates identity/ACL/SCM setup to this command. Automated installation passes the generated password over standard input with `--account-password-stdin`; the password is not placed in the command line, environment, or a temporary file.

The low-level `wd-agent service install` command intentionally still does not create accounts or grant user rights itself. Without `--account-password-stdin` it retains the existing hidden interactive password prompt.

## Current limitations

- Identity private keys are filesystem-protected and are not TPM/CNG-backed yet.
- The service log is a local text file rather than Windows Event Log.
- Authenticode signing and MSI/WiX packaging are not implemented yet.
