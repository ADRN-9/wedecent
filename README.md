# WeDecent

WeDecent is a transport-independent secure remote terminal and routed-access system built around cryptographic device identity rather than network location.

The current release candidate is **v0.4.4**. It includes native terminal support on Linux, Windows, and macOS; protected Local Core IPC; direct, relay, and trusted one-hop routed connectivity; service packaging; persistent audit controls; and a signed Windows release/update pipeline.

## What works now

- Linux PTY, Windows ConPTY, and macOS PTY terminal sessions
- native raw-terminal/password handling and resize propagation on Linux, Windows, and macOS clients
- Ed25519 device identity with deterministic device IDs and SHA-256 SPKI fingerprints
- TLS 1.3 endpoint encryption and exact public-key pinning
- 192-bit single-use pairing secrets
- signed LAN discovery
- direct TCP/LAN connectivity
- outbound-only relay connectivity, including Cloudflare Workers + Durable Objects over secure WebSockets
- short-lived Ed25519 proof-of-possession relay tickets and account-authorized connection grants
- trusted one-hop A -> B -> C routing with separate routing trust domains and short-lived signed `mesh.forward` capabilities
- protected per-user Local Core IPC with bounded request/response framing
- Windows Local Core GUI prototype that talks only to Local Core and does not own networking/trust authority
- authenticated router administration over machine-local IPC with a dedicated controller trust domain
- persistent structured security audit events
- relay rate limiting, health/metrics/tracing, bounded replay state, and session duration policy
- hardened configuration/state-file handling and protocol fuzz/compatibility gates
- Windows DPAPI-protected identity keys with plaintext migration; hardened owner-only identity files on non-Windows systems
- Windows SCM service mode plus hardened Linux systemd and per-user macOS LaunchAgent packaging
- reproducible Windows release/installer bundles, Authenticode finalization, immutable publication checks, signed stable-manifest verification, rollback protection, verified installer staging/application, and post-success sequence commit

## Deliberately incomplete or externally blocked

The core v0.4.4 repository is release-candidate ready, but these boundaries are intentionally not represented as complete:

- Windows non-exportable TPM/CNG Ed25519 identity keys are blocked by current native Windows algorithm support while WeDecent preserves exact Ed25519 identity semantics; tracked in issue #84.
- Non-Windows platform-backed/non-exportable Ed25519 identity storage requires a service-safe design that does not depend on desktop keychain sessions or shell helpers; tracked in issue #92.
- The production stable-update public-key pin, production external signer, and atomic manifest/signature publisher must be provisioned outside the repository under an explicit production change; tracked in issue #93.
- Bluetooth/USB transports, a full PuTTY-style desktop product, and the managed team control plane remain later roadmap phases.

## Build and validate

Use Go 1.27.0 or newer within the Go 1.27 release line.

```bash
make vet
make test
make build
make smoke-direct
make smoke-relay
```

The repository currently uses pinned Go dependencies including `github.com/Microsoft/go-winio` and `golang.org/x/sys`.

Binaries are written to `./bin`:

- `wd` — client CLI
- `wd-agent` — remote terminal/routing agent
- `wd-core` — per-user Local Core process
- `wd-routerctl` — router-controller trust utility
- `wd-ui` — Windows Local Core GUI prototype
- `wd-relay` — standalone relay implementation

## Direct LAN quick start

On the remote machine:

```bash
wd-agent init
wd-agent serve --listen 0.0.0.0:7443 --discover --shell /bin/bash
```

On the client, pair using the expected fingerprint and one-time secret, then connect by device identity:

```bash
wd discover
wd pair --endpoint 192.168.1.50:7443 --fingerprint SHA256:<expected-fingerprint>
wd connect wd_xxxxxxxxxxxxxxxx
```

The saved locator is only a routing hint. Authentication is against the pinned cryptographic identity.

## Outbound-only relay

The agent can run with no inbound terminal listener and maintain outbound relay slots instead. The relay forwards the inner pinned TLS stream and is not trusted with terminal plaintext.

```bash
wd-agent serve --listen '' --web-relay https://relay.wedecent.com --shell /bin/bash
```

Pairing and connection still require the expected endpoint identity and the independent authorization boundaries described in the protocol documentation.

## Service packaging

- Windows: native SCM service mode and installer/package tooling.
- Linux: `installer/linux/` contains the hardened systemd unit and install/uninstall helpers. The service runs as a dedicated non-login `wedecent` account and preserves identity/config/state on uninstall.
- macOS: `installer/macos/` contains a per-user LaunchAgent installer. Root installation is refused so the exposed shell remains the selected user account.

## Security model

1. Each endpoint owns an Ed25519 identity generated locally.
2. Device IDs/fingerprints are derived from the public key and are not inferred from IP addresses or account identity.
3. Self-signed identity certificates are short-lived and verified against the corresponding identity key.
4. Initial terminal trust requires the expected endpoint fingerprint plus a high-entropy single-use pairing secret.
5. Terminal trust, routing trust, and router-administration trust are separate domains.
6. Route authorization and terminal authorization are separate short-lived capabilities.
7. The remote client cannot select an arbitrary executable; the agent operator configures the shell.
8. Direct, relay, and routed transports all terminate in the same endpoint-pinned inner TLS session.

### Operational cautions

- Run `wd-agent` as the OS account whose shell access you intend to expose. Do not run it as root unless root terminal access is explicitly required.
- Protect state directories and backups. Windows identity keys are DPAPI-protected; non-Windows identity files are hardened owner-only files but are not yet platform-backed non-exportable signers.
- Do not provision production signing keys or publisher credentials in the repository.
- Production release/update publication must retain the external signer and atomic compare-and-swap publisher boundaries.
- Signed LAN discovery proves possession of the advertised key; it does not create trust.

See `SECURITY.md`, `docs/PROTOCOL.md`, `docs/ARCHITECTURE.md`, `docs/LOCAL_CORE_API.md`, `docs/ROADMAP.md`, and `docs/RELEASE_READINESS.md` for the detailed boundaries and remaining work.
