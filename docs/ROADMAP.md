# Roadmap

## v0.4.4 core release status

The secure remote-terminal/routed-access core and Phase 2 platform coverage are implemented. The repository can be finalized as a v0.4.4 release candidate once canonical CI passes on the release-readiness change.

The remaining Phase 1.1 checkboxes are external/platform-boundary items rather than missing core transport/session code:

- Windows TPM/CNG non-exportable Ed25519 identity support: issue #84.
- Non-Windows service-safe platform-backed Ed25519 identity storage: issue #92.
- Production stable-update trust/publisher provisioning: issue #93; requires an explicit production change.

Later Phase 3-5 items are product expansion and are not prerequisites for the v0.4.4 secure terminal core.

## Phase 1 — working foundation (implemented)

- [x] Linux PTY
- [x] Framed terminal protocol
- [x] Ed25519 device identity
- [x] TLS 1.3 + SPKI pinning
- [x] Single-use high-entropy pairing
- [x] Direct TCP/LAN
- [x] Signed LAN discovery
- [x] Outbound-only relay
- [x] Relay challenge/signature registration
- [x] Direct/relay locator abstraction

## Phase 1.1 — production hardening

- [x] Persistent structured audit events
- [x] Client/device trust removal and revocation commands
- [x] Relay per-IP/device connection rate limits
- [x] Relay metrics, health endpoints and tracing
- [x] Session idle/max-duration policy
- [x] Config files rather than only CLI flags
- [ ] OS keychain/TPM-backed private keys where available
  - [x] Windows DPAPI protection and plaintext-key migration
  - [ ] TPM/CNG non-exportable Windows Ed25519 keys — blocked/tracked in #84
  - [ ] Non-Windows platform-backed Ed25519 storage with unattended service semantics — tracked in #92
- [x] Fuzz tests for frame and relay-control decoders
- [x] Protocol negotiation/version compatibility tests
- [ ] Signed release/update mechanism
  - [x] Authenticode-signed Windows release and immutable public-download verification
  - [x] Canonical signed stable-channel manifest format with rollback checks
  - [x] Fixed-origin signed manifest discovery and protected sequence-state primitive
  - [ ] Production update-key provisioning and stable-channel manifest publication — tracked in #93
    - [x] Strict public-key artifact format plus external-signer/atomic-publisher tooling
    - [ ] Provision the production client public-key pin and production atomic publisher hook
  - [x] Installer download, verification, application and post-success sequence commit
    - [x] Bounded immutable installer download, manifest SHA-256 verification and private staging
    - [x] Exact package/Authenticode verification immediately before application
    - [x] Installer application, recovery and post-success sequence commit

## Phase 2 — platform coverage (implemented)

- [x] Windows ConPTY agent
- [x] macOS PTY implementation
- [x] Native terminal/raw-mode handling on Windows/macOS clients
- [x] systemd/launchd/Windows Service packaging

## Phase 3 — physical/offline transports

These are post-v0.4.4 transport expansions, not release blockers for the secure terminal core.

### Bluetooth

- [ ] Linux BlueZ RFCOMM adapter
  - [x] Native Linux dial/listen primitives, agent composition, and explicit `wd pair` / `wd connect` selection
  - [x] Hardware-required validation harness and operator procedure
  - [ ] Record a successful authorized terminal run on two real Linux Bluetooth Classic endpoints
- [ ] Windows Bluetooth Classic adapter
  - [x] Native Winsock RFCOMM dial/listen primitives using the existing locator, agent composition, and `wd pair` / `wd connect` selection
  - [x] Hardware-required validation harness and operator procedure
  - [ ] Record a successful authorized terminal run with a real Windows Bluetooth Classic endpoint
- [x] L2CAP CoC evaluation for platforms where it is preferable
  - [x] Native Linux and Apple APIs are viable but require an explicit packet-to-stream/platform bridge
  - [x] Defer implementation while Windows lacks a comparably narrow user-mode CoC path and no concrete BLE-only endpoint requires it; see `L2CAP_COC_EVALUATION.md`
- [x] Pair/transport discovery UX
  - [x] Define the discovery-versus-trust contract, ambiguity handling, and fail-closed selection rules; see `TRANSPORT_DISCOVERY.md`
  - [x] Add deterministic first-pair LAN candidate selection that rejects identity conflicts, malformed endpoints, and ambiguous locators
  - [x] Add bounded first-pair LAN candidate collection that preserves conflicting/ambiguous candidates through the full discovery window
  - [x] Wire explicit `wd pair --discover-lan --device-id ... --fingerprint ...` with strict transport mutual exclusion and no fallback
  - [x] Defer richer Bluetooth/USB enumeration to the Phase 4 desktop picker with explicit reopen criteria; see `TRANSPORT_DISCOVERY.md`

### USB

- [ ] USB CDC-ACM serial adapter
  - [x] Linux serial dialer, strict locator, explicit `wd pair` / `wd connect` selection, and agent composition
  - [x] Hardware-required validation harness and operator procedure
  - [ ] Record a successful authorized terminal run over real USB CDC-ACM endpoints
- [ ] Linux USB gadget mode documentation/helper
  - [x] Guarded configfs CDC-ACM setup/status/teardown helper and operator documentation
  - [ ] Record successful real UDC enumeration and authorized CDC-ACM terminal validation
- [ ] USB networking adapter as a simpler high-throughput path
  - [x] Guarded Linux configfs NCM function helper with explicit UDC/MAC/VID/PID and no host-network mutation
  - [x] Reuse existing pinned direct-TCP transport over an operator-configured point-to-point IP link
  - [ ] Record successful real NCM enumeration and authorized direct-TCP terminal validation over USB
- [x] Evaluate direct bulk-endpoint transport practicality
  - [x] Linux FunctionFS/usbfs feasibility and cross-platform host-driver implications documented
  - [x] Defer first-class bulk transport until a concrete hardware requirement and supportable driver/user-mode deployment path exist; prefer NCM for current high-throughput USB use cases

A normal passive USB-C cable between two ordinary USB-host PCs is not sufficient unless one side supports USB device/gadget/dual-role mode.

## Phase 4 — PuTTY-style desktop product

- [ ] Tauri desktop shell
  - [x] Freeze the client-only desktop authority/process boundary and completion criteria; see `DESKTOP_SHELL.md`
  - [x] Add the minimal Tauri v2 shell scaffold without transport/trust/runtime logic
  - [x] Add a read-only, sanitized status bridge over the existing protected Local Core client
  - [ ] Connect the shell through the approved Local Core application boundary and exercise it in canonical CI
- [ ] xterm.js terminal renderer
- [ ] Device list + transport/latency badges
- [ ] Tabs and multiple terminal streams per secure connection
- [ ] Session profiles
- [ ] File transfer
- [ ] Local/remote port forwarding

## Phase 5 — team control plane

- [x] Supabase account-authorization schema + RLS foundation
- [ ] `app.wedecent.com`
- [ ] OIDC/SAML SSO
- [ ] Organizations/users/devices
- [ ] RBAC and device groups
- [ ] Enrollment tokens / managed provisioning
- [ ] Audit/search/retention policies
- [ ] Multi-region relays and relay selection
