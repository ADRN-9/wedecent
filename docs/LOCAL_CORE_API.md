# Local Core API

## Status

This document defines the first contract slice for the v0.4.4 Local Core API.

The initial implementation is intentionally transport-neutral. It adds versioned Go request/response types and a `Service` interface under `internal/coreapi/v1`; it does not start a listener, expose a network port, or change the existing `wd` connection path.

## Purpose

Desktop and mobile interfaces must call the WeDecent core rather than reimplementing identity, authorization, route selection, relay protocols, or cryptography.

The first contract covers:

- core/account status without bearer credentials
- device listing and device details
- connect/disconnect requests
- transport status
- route status
- router policy
- router statistics

The core remains responsible for choosing and authenticating the actual connection path.

## Versioning

The first contract is `v1` and lives in:

```text
internal/coreapi/v1
```

Wire names are explicit JSON tags so a later IPC adapter can preserve the contract across UI implementations. Additive fields may be introduced within `v1`; incompatible semantic or wire changes require a new API version.

## Security boundary

The Local Core API must never return:

- device private keys
- TLS private keys
- Supabase access or refresh tokens
- account passwords
- connection-grant JWTs
- route-authorization signing keys
- relay authentication secrets

The API may return non-secret identifiers such as device IDs, public-key fingerprints, route hops, selected path type, and account email/user ID.

Credential-bearing sign-in is deliberately excluded from this first contract slice. Before adding it, the local transport must define same-user access control, request-size limits, secret redaction, logging rules, and platform-specific endpoint permissions. No generic TCP listener should be introduced merely to carry credentials locally.

## Connection semantics

A `Connect` request names the destination device. The UI does not choose cryptographic grants or construct routes. The core owns path selection and can report the resulting path as one of:

```text
direct
lan
routed
relay
```

This keeps UI behavior independent of transport details and allows the core to preserve the existing fail-closed authorization and fallback behavior.

## Router policy

The API exposes a stable copy of router policy fields rather than leaking internal mesh implementation types directly. Router participation remains explicit opt-in, and public routing must never be enabled implicitly.

## Next slices

After the contract is reviewed and CI is green:

1. implement a core service backed by the existing account, trust, transport, mesh, and session packages;
2. define a protected local IPC transport (Windows named pipe and Unix-domain socket are preferred candidates);
3. add credential-bearing sign-in/out with explicit secret-handling tests;
4. wire the Windows GUI prototype to the same `v1` service contract.

The existing CLI and staging-tested routed-terminal path remain the compatibility baseline throughout this work.
