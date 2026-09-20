# Local Core API

## Status

This document defines the v0.4.4 Local Core API.

The current implementation provides versioned Go request/response types under `internal/coreapi/v1`, a read-only core service for status and trusted-device inspection, a transport-neutral bounded IPC protocol for those read operations, protected per-user local IPC endpoint factories, a bounded server lifecycle around those endpoints, and a manually-started `wd-core` process that composes them. It does not install or autostart a daemon, expose a network port, or change the existing `wd` connection path.

## Purpose

Desktop and mobile interfaces must call the WeDecent core rather than reimplementing identity, authorization, route selection, relay protocols, or cryptography.

The `v1` contract covers:

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

Wire names are explicit JSON tags. Additive fields may be introduced within `v1`; incompatible semantic or wire changes require a new API version.

The aggregate `Service` interface is split into capability interfaces so implementations can be built and tested incrementally without adding placeholder operations.

## Read-only service

`internal/coreapi.ReadService` implements the `StatusService` and `DeviceService` capabilities using the existing identity, account-session, and trust-store types.

It snapshots only the public identity/account fields required by the UI. It does not retain the device identity object or account session object, so private keys and bearer tokens are not kept in the UI-facing service.

Device lists are sorted by device ID before being returned, giving UI clients deterministic results even though the trust store is map-backed.

## IPC protocol

`internal/coreapi/ipc` defines transport-neutral framing and read-only dispatch. It deliberately does not create or listen on a socket.

Each message is a four-byte big-endian length followed by one JSON object. Frames are capped at 64 KiB before allocation. Request envelopes require an exact API version, bounded request ID, bounded method name, and strictly decoded parameters. Unknown JSON fields and multiple JSON values are rejected.

The first wire methods are:

```text
status.get
devices.list
device.get
```

Backend errors are mapped to stable public error codes instead of returning raw error strings. Unexpected failures therefore do not expose tokens, paths, database details, or other internal data.

## Local transport boundary

`internal/coreapi/localipc` supplies protected per-user listener and dialer factories without opening an IP socket.

On Windows, the endpoint is a named pipe. Its name contains a truncated SHA-256 digest of the current user's SID rather than the raw SID. The pipe DACL grants access only to that SID, and the named-pipe implementation rejects remote clients. The Local Core endpoint is intentionally separate from `wd-agent`: the existing Windows agent runs under a dedicated service account, while GUI-facing Local Core IPC belongs to the interactive user's security boundary.

On Unix-like systems, the endpoint is `core-v1.sock` under the per-user core state directory. The directory must be absolute, owned by the effective user, and mode `0700`; the socket must be owned by the effective user and mode `0600`. Symlinked or otherwise unsafe endpoint state is rejected. An owned stale socket may be removed only after it refuses a local connection; a live endpoint is never replaced.

A generic localhost TCP listener is not an acceptable credential transport.

## Server lifecycle

`internal/coreapi/localserver` owns the lifecycle around an already-created protected local listener. It does not choose or open the transport itself.

The lifecycle is intentionally bounded:

- the caller supplies explicit concurrency and per-request timeout limits;
- configuration with zero or excessive limits is rejected instead of becoming unbounded;
- a concurrency slot is reserved before `Accept`, which prevents an unlimited queue of accepted connections inside the process;
- each accepted connection receives an I/O deadline and a request context deadline;
- each connection serves exactly one request/response exchange and is then closed;
- malformed requests, protocol errors, backend errors, and handler panics are isolated to the affected connection;
- request bodies and raw handler errors are not logged by the lifecycle layer;
- cancellation closes the listener and all active connections, unblocking pending I/O before shutdown waits for request goroutines.

This layer remains reusable library code. It does not install, autostart, or background a Local Core process, and it does not add credential-bearing methods.

## Read-only Local Core process

`cmd/wd-core` is the first manually-started per-user Local Core process. It composes the existing read-only service, protected `localipc` endpoint, IPC dispatcher, and `localserver` lifecycle.

Startup is intentionally non-creating for identity state. `identity.Load` requires an existing key and certificate, rejects symlinked identity files, verifies that the certificate and private key match, and does not create or renew identity material. Starting the UI-facing core therefore cannot silently create or rotate a device identity.

The process may read an existing account session to report non-secret account status, but it does not refresh, rewrite, log, or return access/refresh tokens. A missing account session is treated as signed out. The trusted-device store is opened from the existing client state and is only exposed through read operations in this slice.

`wd-core` uses `localserver.DefaultConfig`, so connections inherit the shared concurrency bound, request timeout, panic isolation, active-connection shutdown, and one-request-per-connection behavior. Interrupt cancellation closes the protected listener and drains active requests through the shared lifecycle.

This slice still exposes read-only methods only. It does not install or autostart `wd-core`, and credential-bearing methods remain disabled.

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

Credential-bearing sign-in is deliberately excluded until its secret-handling behavior is explicitly tested over the protected process boundary. Before adding it, the API must define password lifetime, token persistence, redaction, logging behavior, cancellation, and failure semantics.

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

1. add credential-bearing sign-in/out with explicit secret-redaction, password-lifetime, persistence, cancellation, and failure tests;
2. add transport and route-status readers backed by the existing transport/mesh state;
3. implement connection lifecycle behind the existing session and route-authorization code paths;
4. add router policy/statistics service implementations;
5. wire the Windows GUI prototype to the same `v1` service contract.

The existing CLI and staging-tested routed-terminal path remain the compatibility baseline throughout this work.
