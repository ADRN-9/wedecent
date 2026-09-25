# v0.4.4 Release Readiness

This document defines the repository-side completion boundary for the WeDecent v0.4.4 secure remote-terminal/routed-access core.

## Release candidate scope

v0.4.4 includes:

- Linux PTY, Windows ConPTY, and macOS PTY terminal endpoints
- native client terminal/raw-mode/resize support across Linux, Windows, and macOS
- Ed25519 device identity, exact fingerprint pinning, TLS 1.3, pairing, trust revocation, and persistent audit events
- direct LAN, outbound relay, and trusted one-hop routed terminal connectivity
- separate terminal, routing, and router-administration trust domains
- protected Local Core IPC and bounded terminal streaming
- Windows GUI prototype consuming Local Core only
- hardened Windows SCM, Linux systemd, and macOS LaunchAgent packaging
- relay rate limits/metrics/health/tracing and session duration controls
- protocol compatibility/fuzz/race/smoke gates
- reproducible Windows release/installer generation and credential-agnostic signing/publication tooling
- signed stable-update manifest verification, rollback protection, installer verification/application, and sequence commit

## Canonical repository release gate

A release candidate is repository-ready only when all of the following are true on one immutable candidate commit:

1. `VERSION` matches the intended candidate/release version.
2. The branch is exactly based on current `main`, with an auditable release-readiness delta.
3. Canonical GitHub CI passes on the exact candidate head, including:
   - Linux formatting and vet
   - Unix service-packaging regression
   - protocol compatibility and fuzz gates
   - `go test -race ./...`
   - direct and outbound-relay smoke tests
   - native Windows tests/builds
   - Windows release/signing/publication/package fixtures
   - native macOS tests/builds
   - routed capability and A -> B -> C E2E gates
   - relay worker tests
   - control-plane checks
   - disposable Supabase database/pgTAP tests
4. There are no unresolved PR review threads or merge blockers.
5. `README.md`, `SECURITY.md`, and `docs/ROADMAP.md` describe the candidate accurately.
6. No production secret, signing private key, cloud credential, or production publisher hook is committed.

## Known non-code blockers / deferred security enhancements

These do not invalidate the repository-side v0.4.4 candidate, but they must remain visible and must not be represented as complete:

- **#84 — Windows TPM/CNG Ed25519:** built-in Windows platform support does not currently provide the required persistent non-exportable Ed25519 signer while preserving existing device IDs/fingerprints.
- **#92 — non-Windows platform-backed identity storage:** requires a service-safe design preserving unattended startup and exact Ed25519 identity semantics.
- **#93 — production stable-update trust/publisher:** requires production key provisioning, client public-key pin provisioning, Authenticode production policy, and an atomic external publisher. This is an explicit production change.

## Production-release boundary

Repository readiness is not the same as production publication.

Before a production stable update can be called complete, #93 must be performed under explicit production authorization and the resulting public stable manifest/signature must be verified from the fixed origin with rollback protection intact.

Do not work around this boundary by:

- committing a production private key or cloud credential
- accepting a key delivered by the update manifest itself
- using an overwrite-capable publisher fallback
- uploading the manifest and signature as independent mutable writes
- changing the device identity algorithm to satisfy a platform key-store limitation

## Post-v0.4.4 roadmap

Bluetooth/USB transports, the full PuTTY-style desktop product, and the managed team control plane are product-expansion phases. They are not prerequisites for finalizing the v0.4.4 secure terminal core and should ship behind their own scoped review/security gates.
