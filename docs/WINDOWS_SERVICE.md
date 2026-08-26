# Windows service mode

The `feature/windows-service` development branch adds native Windows Service Control Manager (SCM) integration to `wd-agent` without adding third-party Go dependencies.

## Security model

The service deliberately refuses the built-in `LocalSystem`, `LocalService`, and `NetworkService` identities. Install it under a dedicated standard Windows account whose permissions match the shell access you intend to expose.

The relay access token is not stored in the service command line or environment. `wd-agent service install` encrypts it with Windows DPAPI using machine scope and stores the encrypted blob under the service state directory. The state directory ACL is then restricted to:

- the configured service account;
- LocalSystem;
- local Administrators.

Machine-scope DPAPI means filesystem ACLs are part of the credential boundary. Do not loosen the state-directory ACL.

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

The installer prompts without echo for:

1. the WeDecent relay token;
2. the service-account password.

It then:

- creates/loads the machine-wide device identity;
- creates a new one-time pairing secret;
- stores the relay token as a DPAPI-protected blob;
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

## Rotate the relay credential

Run from elevated PowerShell:

```powershell
.\wd-agent.exe service credential set --account ".\\WeDecentSvc"
.\wd-agent.exe service stop
.\wd-agent.exe service start
```

The credential command overwrites the DPAPI-protected relay-token blob and reapplies the state-directory ACL. The service must be restarted to load the new value.

## Service runtime

The SCM starts the binary with the internal command:

```text
wd-agent.exe service run ...
```

Do not invoke `service run` manually. It connects to the Windows SCM, reports start/running/stop states, and translates SCM stop/shutdown requests into context cancellation for the normal WeDecent agent runtime.

The existing interactive command remains available and unchanged:

```powershell
$env:WEDECENT_RELAY_TOKEN = Read-Host "Relay token"
.\wd-agent.exe serve --listen= --web-relay=https://relay.wedecent.com --relay-slots=4
```

Environment-variable credentials are intended for development only. Service deployments should use the protected credential store.

## Current limitations

- The installer does not create the Windows user account.
- The installer does not grant the **Log on as a service** right automatically.
- Credential protection uses DPAPI machine scope plus an ACL, not TPM/CNG-backed keys.
- The service log is a local text file rather than Windows Event Log.
- Code signing and MSI packaging are not implemented yet.
