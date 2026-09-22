# Local Core API

## Status

This document defines the v0.4.4 Local Core API.

The current implementation provides versioned Go request/response types under `internal/coreapi/v1`, status and trusted-device inspection, credential-bearing account sign-in/sign-out, transport capability and ephemeral route/path inspection, a bounded IPC protocol, protected per-user local IPC endpoints, a bounded server lifecycle, and a manually-started `wd-core` process that composes them. It does not install or autostart a daemon, expose a network port, or change the existing `wd` connection path.

## Purpose

Desktop and mobile interfaces must call the WeDecent core rather than reimplementing identity, authorization, route selection, relay protocols, account-session handling, or cryptography.

The `v1` contract covers:

- core/account status without bearer credentials
- account sign-in and sign-out over protected local IPC
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

## Status and device service

`internal/coreapi.ReadService` implements the `StatusService` and `DeviceService` capabilities using the existing identity, account-session, and trust-store types.

It retains only the public identity/account fields required by the UI. It does not retain the device identity object or account-session object, so private keys and bearer tokens are not kept in the UI-facing read service. Account identity fields are updated under a lock after successful sign-in/sign-out so `status.get` reflects the current process state without racing concurrent readers.

Device lists are sorted by device ID before being returned, giving UI clients deterministic results even though the trust store is map-backed.

## IPC protocol

`internal/coreapi/ipc` defines transport-neutral framing and dispatch. It deliberately does not create or listen on a socket.

Each message is a four-byte big-endian length followed by one JSON object. Frames are capped at 64 KiB before allocation. Request envelopes require an exact API version, bounded request ID, bounded method name, and strictly decoded parameters. Unknown JSON fields and multiple JSON values are rejected.

The implemented wire methods are:

```text
status.get
account.sign_in
account.sign_out
devices.list
device.get
transports.list
route.get
```

Backend errors are mapped to stable public error codes instead of returning raw error strings. Unexpected failures therefore do not expose tokens, passwords, paths, database details, or other internal data. A missing or expired route is reported as the stable `route_not_found` error rather than leaking internal route state.

After a framed request is strictly decoded, the raw frame buffer is overwritten before `ReadRequest` returns. For `account.sign_in`, the copied raw `params` buffer is also overwritten immediately after strict parameter decoding. The decoded password is cleared from local variables as soon as practical. This is best-effort memory hygiene, not a guarantee of cryptographic zeroization: Go strings are immutable values managed by the runtime, and copies may exist until garbage collection.

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

This lifecycle remains reusable library code. It does not install, autostart, or background a Local Core process.

## Local Core process

`cmd/wd-core` is the manually-started per-user Local Core process. It composes the existing status/device service, network read service, protected `localipc` endpoint, IPC dispatcher, account service, and `localserver` lifecycle.

Startup is intentionally non-creating for identity state. `identity.Load` requires an existing key and certificate, rejects symlinked identity files, verifies that the certificate and private key match, and does not create or renew identity material. Starting the UI-facing core therefore cannot silently create or rotate a device identity.

An existing account session is loaded to initialize non-secret account status and the account service. If no account session exists, the process starts signed out. Supabase URL and publishable-key configuration can be supplied to `wd-core` through the existing flags/environment variables; when an existing session is present, its project URL and publishable key are used as defaults if explicit configuration is absent. The UI does not send project configuration over the account IPC methods.

`wd-core` uses `localserver.DefaultConfig`, so connections inherit the shared concurrency bound, request timeout, panic isolation, active-connection shutdown, and one-request-per-connection behavior. Interrupt cancellation closes the protected listener and drains active requests through the shared lifecycle.

`wd-core` is still manually started in this milestone. It is not installed or autostarted.

## Account authentication

`account.sign_in` accepts only an email address and password. The core validates bounded input, requires configured Supabase project information, calls the existing `account.Client.Login`, and persists the resulting account session before publishing signed-in status. If login or persistence fails, signed-in status is not published and backend error details are sanitized at the IPC boundary.

The account session remains inside the core and existing account-session storage. On Windows, access and refresh tokens are protected with the current user's DPAPI context before being written. On Unix-like systems, the existing store is a permission-protected JSON file that must not be accessible to group or other users (`0600`); it is not encrypted at rest by this layer.

`account.sign_out` treats local session removal as authoritative. The core attempts session refresh and remote Supabase logout on a best-effort basis, then removes the local protected session and clears observable signed-in status. A network outage or remote logout failure therefore does not trap the user in a locally signed-in state. A request that is already canceled before sign-out begins does not mutate the local session.

No account IPC response contains an access token, refresh token, password, or other credential. Successful sign-in/sign-out responses use the ordinary non-secret `Status` shape.

## Transport and route status

`internal/coreapi.NetworkReadService` implements the `TransportService` and `RouteService` read capabilities. It performs no discovery, dialing, reachability probing, grant issuance, route authorization, or route selection.

`transports.list` returns transport classes in deterministic order. In this API, `available` means that the transport class is implemented by the current core build and can be used by core networking logic; it does **not** mean that the Internet is reachable, that LAN discovery currently finds a peer, or that a specific destination can be contacted. The current build reports LAN and Internet support and reports Bluetooth as unavailable because Bluetooth transport is not implemented yet.

`route.get` accepts a Local Core connection ID and returns only non-secret path metadata. Path state is process-local and ephemeral; it is not written to disk. The service is designed to be updated by the connection-lifecycle layer after that layer has selected and authenticated a path.

For routed connections, UI-visible hops are derived from the existing validated `mesh.Route` structure. The route must match the local source and requested destination and must still be unexpired before it can be published. Returned hop slices are copied so callers cannot mutate core state. When a route reaches its expiry, the stored status is removed and subsequent reads fail closed with `route_not_found`.

Non-routed `direct`, `lan`, and `relay` path snapshots contain no mesh-route hops, router ID, or route expiry. A non-routed snapshot that attempts to attach a mesh route is rejected.

The Local Core does not yet implement the general `Connect`/`Disconnect` lifecycle in this slice, so a newly started `wd-core` has no active route/path records and `route.get` returns `route_not_found` until a future connection-lifecycle implementation records one. The existing CLI and staging-tested connection paths are unchanged.

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

Credential-bearing account input is accepted only over the protected per-user IPC boundary. It must not be logged, copied into diagnostic errors, exposed through status, or forwarded to UI-visible responses.

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

1. implement connection lifecycle behind the existing session and route-authorization code paths and feed authenticated path state into `NetworkReadService`;
2. add router policy/statistics service implementations;
3. wire the Windows GUI prototype to the same `v1` service contract;
4. decide installation/autostart behavior only after process lifecycle and upgrade behavior are explicitly designed and tested.

The existing CLI and staging-tested routed-terminal path remain the compatibility baseline throughout this work.
