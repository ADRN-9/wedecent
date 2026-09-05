# Windows ConPTY development

The v0.3 development branch adds a native Windows terminal backend using the Windows Pseudoconsole (ConPTY) API. Native ConPTY + Windows PowerShell has been validated end to end through the serverless relay.

## Target

- Windows 10 version 1809 or newer
- Windows 11
- PowerShell as the default shell
- No WSL requirement
- Same WeDecent pairing, TLS identity, and WebSocket relay protocol as Linux

## Development test

Build on Windows with Go 1.27.0:

```powershell
go test ./...
go build -trimpath -o bin\wd-agent.exe .\cmd\wd-agent
```

Initialize:

```powershell
.\bin\wd-agent.exe init --name windows-test
```

Run outbound-only:

```powershell
.\bin\wd-agent.exe serve --listen "" --web-relay https://relay.wedecent.com --relay-slots 4
```

The default remote shell is Windows PowerShell through ConPTY.

## Security notes

Do not run the agent as LocalSystem during development. Use a dedicated standard user. Production service mode must define an explicit account and ACL the state directory. Relay-auth-v2 uses the machine Ed25519 identity for short-lived relay tickets, so no shared relay secret is required. See `WINDOWS_SERVICE.md`.
