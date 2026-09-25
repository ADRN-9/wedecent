# Security Notes

WeDecent v0.4.4 is a security-sensitive remote-access release candidate. Privileged production deployment should still receive an independent security review and an operator-specific deployment review.

## Current protections

- TLS 1.3 endpoint sessions with exact SPKI public-key pinning
- Ed25519 endpoint identities generated locally
- strict separation of terminal trust, routing trust, and router-administration trust
- 192-bit random single-use pairing secrets; only hashes are retained
- fixed operator-configured shell; remote clients cannot submit executable paths or shell command strings
- bounded framed protocols with strict decoding and compatibility/fuzz gates
- persistent structured audit events for security-sensitive mutations/lifecycle events
- direct/listener concurrency bounds and session idle/max-duration policy
- relay per-IP/device rate limits, health/metrics/tracing, parked-slot limits, and bounded replay protection
- short-lived Ed25519 proof-of-possession relay tickets and short-lived account-authorized terminal connection grants
- one-hop route capabilities separately signed for `mesh.forward`, with exact route binding and durable replay protection
- router administration over machine-local IPC with TLS 1.3, dedicated ALPN, exact controller trust, and no TCP fallback
- protected per-user Local Core IPC; UI-facing APIs expose no private keys, bearer tokens, passwords, route capabilities, or raw trust stores
- Local Core terminal I/O bounds, bounded retained output, and idempotency protection for ambiguous connect/write outcomes
- Windows identity keys protected with machine-scope DPAPI plus restrictive state ACLs; legacy plaintext migration preserves the exact Ed25519 identity
- non-Windows identity files use owner-only permissions, bounded descriptor-backed reads, symlink/path-swap rejection, and atomic no-replace first creation
- identity certificates are bounded, descriptor-verified, single-PEM files with self-signature validation and exact public-key matching
- Windows account sessions protected with CurrentUser DPAPI; Unix-like account sessions remain owner-only files
- hardened systemd/LaunchAgent/Windows Service packaging that preserves identity/config/state on uninstall
- reproducible Windows release/installer generation, Authenticode finalization/verification, immutable public-object checks, signed stable manifests, rollback state, verified installer staging/application, and post-success sequence commit

## Remaining security boundaries

### Platform-backed identity keys

The current device identity algorithm is Ed25519 and its public key defines the device ID/fingerprint. We do not silently substitute RSA/ECDSA to satisfy a platform key store.

- Windows DPAPI protection is implemented, but a persistent non-exportable native TPM/CNG Ed25519 signer is not currently available through the built-in Windows platform boundary used by this project. Tracked in issue #84.
- Non-Windows platform-backed/non-exportable storage remains open. Any solution must preserve unattended systemd/LaunchAgent startup and exact Ed25519 identity semantics rather than depending on a desktop Secret Service session or shell helper. Tracked in issue #92.

### Production update trust provisioning

The repository contains the signed-update mechanism and credential-agnostic signer/publisher boundaries, but the real production trust anchor and publisher are intentionally not committed or auto-provisioned.

- production stable-update Ed25519 key material must remain outside the repository
- the exact production public-key pin must be provisioned into the production release/client boundary
- the production manifest/signature publisher must implement the documented atomic compare-and-swap pair update
- production Authenticode verifier policy must enforce the intended publisher chain/identity/timestamp policy

Tracked in issue #93. Production provisioning/publication requires an explicit production change.

### Host privilege and containment

- The spawned shell has the privileges of the `wd-agent` OS account. WeDecent does not provide an additional shell sandbox.
- Operators must choose the service account deliberately and protect its state, configuration, backups, and host login boundary.
- File transfer and port forwarding are not part of the current core release, so their future path/authorization policy remains to be designed before those roadmap features are enabled.

### External infrastructure

- Public relay and control-plane deployments retain their own cloud/provider operational security boundaries, credentials, certificate rotation, monitoring, incident response, and capacity planning.
- Multi-region relay selection and the full managed-team control plane remain later roadmap work.

## Threat model note

The relay is not trusted with terminal plaintext. It necessarily observes routing metadata such as target device IDs, connection timing, source addresses, and byte-flow characteristics. The inner endpoint-pinned TLS session protects terminal content and endpoint credentials from the relay.

A router in the one-hop A -> B -> C model authenticates/authorizes forwarding but does not terminate the inner A <-> C terminal TLS session.

## Local Core / UI boundary

The Local Core owns authenticated connection establishment, authorization requests, route selection, endpoint pinning, terminal handles, and router-admin proxying. The GUI receives opaque connection IDs and bounded non-secret status/terminal data only. The GUI must not become an alternate trust/network authority.

## Account/control-plane boundary

Supabase RLS protects exposed control-plane tables. Sensitive issuance/enrollment operations remain server-controlled: an authenticated browser/user session is not sufficient to claim a cryptographic device identity or mint route/terminal capabilities without the corresponding server-side authorization checks.

See `docs/ACCOUNT_AUTHORIZATION.md`, `docs/ARCHITECTURE.md`, `docs/LOCAL_CORE_API.md`, `docs/ROADMAP.md`, and `docs/RELEASE_READINESS.md`.
