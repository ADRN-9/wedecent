# Roadmap

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
  - [ ] TPM/CNG non-exportable Windows keys and non-Windows platform stores
- [x] Fuzz tests for frame and relay-control decoders
- [x] Protocol negotiation/version compatibility tests
- [ ] Signed release/update mechanism
  - [x] Authenticode-signed Windows release and immutable public-download verification
  - [x] Canonical signed stable-channel manifest format with rollback checks
  - [ ] Network discovery, protected sequence persistence, installer download/application

## Phase 2 — platform coverage

- [ ] Windows ConPTY agent
- [ ] macOS PTY implementation
- [ ] Native terminal/raw-mode handling on Windows/macOS clients
- [ ] systemd/launchd/Windows Service packaging

## Phase 3 — physical/offline transports

### Bluetooth

- [ ] Linux BlueZ RFCOMM adapter
- [ ] Windows Bluetooth Classic adapter
- [ ] L2CAP CoC evaluation for platforms where it is preferable
- [ ] Pair/transport discovery UX

### USB

- [ ] USB CDC-ACM serial adapter
- [ ] Linux USB gadget mode documentation/helper
- [ ] USB networking adapter as a simpler high-throughput path
- [ ] Direct bulk-endpoint transport only where driver/user-mode support is practical

A normal passive USB-C cable between two ordinary USB-host PCs is not sufficient unless one side supports USB device/gadget/dual-role mode.

## Phase 4 — PuTTY-style desktop product

- [ ] Tauri desktop shell
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
