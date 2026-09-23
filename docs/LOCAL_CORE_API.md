# Local Core API

## Status

This document defines the v0.4.4 Local Core API.

The current implementation provides versioned Go request/response types under `internal/coreapi/v1`, status and trusted-device inspection, credential-bearing account sign-in/sign-out, transport capability and ephemeral route/path inspection, a bounded connection-lifecycle manager, a concrete authenticated connection backend, source-bound policy-backed one-hop route selection, authoritative router policy/statistics proxying, an explicit bounded terminal-stream API, a bounded IPC protocol, protected per-user local IPC endpoints, a bounded server lifecycle, and a manually-started `wd-core` process that composes the currently enabled capabilities. It does not install or autostart a daemon or expose a network port.

## Purpose

Desktop and mobile interfaces must call the WeDecent core rather than reimplementing identity, authorization, route selection, relay protocols, account-session handling, terminal protocol framing, or cryptography.

The `v1` contract covers:

- core/account status without bearer credentials
- account sign-in and sign-out over protected local IPC
- device listing and device details
- connect/disconnect requests
- bounded terminal read/write/resize operations for an existing connection
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

The dispatcher recognizes these wire methods when their corresponding capabilities are composed:

```text
status.get
account.sign_in
account.sign_out
devices.list
device.get
transports.list
route.get
connection.connect
connection.disconnect
terminal.read
terminal.write
terminal.resize
router.policy.get
router.policy.set
router.stats.get
```

Backend errors are mapped to stable public error codes instead of returning raw error strings. Unexpected failures therefore do not expose tokens, passwords, paths, database details, transport internals, terminal transport failures, or other private implementation data. Missing or expired routes and missing connections use stable public not-found errors. Connection-capacity, unavailable-service, connection-operation, terminal-unavailable, terminal-operation, and router-operation failures are represented by stable public codes.

After a framed request is strictly decoded, the raw frame buffer is overwritten before `ReadRequest` returns. For `account.sign_in`, the copied raw `params` buffer is also overwritten immediately after strict parameter decoding and the decoded password is cleared from local variables as soon as practical. `terminal.write` similarly wipes its copied raw parameter buffer and decoded input bytes after dispatch. This is best-effort memory hygiene, not a guarantee of cryptographic zeroization: Go values may have runtime-managed copies until garbage collection.

## Local transport boundary

`internal/coreapi/localipc` supplies protected per-user listener and dialer factories without opening an IP socket.

On Windows, the endpoint is a named pipe. Its name contains a truncated SHA-256 digest of the current user's SID rather than the raw SID. The pipe DACL grants access only to that SID, and the named-pipe implementation rejects remote clients. The Local Core endpoint is intentionally separate from `wd-agent`: the agent may run under a dedicated service account, while GUI-facing Local Core IPC belongs to the interactive user's security boundary.

On Unix-like systems, the endpoint is `core-v1.sock` under the per-user core state directory. The directory must be absolute, owned by the effective user, and mode `0700`; the socket must be owned by the effective user and mode `0600`. Symlinked or otherwise unsafe endpoint state is rejected. An owned stale socket may be removed only after it refuses a local connection; a live endpoint is never replaced.

A generic localhost TCP listener is not an acceptable credential or terminal-input transport.

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

`terminal.read` uses the ordinary bounded request lifecycle rather than converting the local IPC connection into a long-lived bidirectional stream. An idle read waits for output or remote close for about one second, then returns an empty result with `closed=false`; this long-poll interval stays below the default five-second Local Core request deadline. Parent request cancellation or shutdown still aborts the read immediately.

## Local Core process

`cmd/wd-core` is the manually-started per-user Local Core process. It composes the status/device service, network read service, protected `localipc` endpoint, IPC dispatcher, account service, authenticated connection backend, policy-backed route source, connection/terminal manager, optional router service proxy, and `localserver` lifecycle.

Startup is intentionally non-creating for identity state. `identity.Load` requires an existing key and certificate, rejects symlinked identity files, verifies that the certificate and private key match, and does not create or renew identity material. Starting the UI-facing core therefore cannot silently create or rotate a device identity.

An existing account session is loaded to initialize non-secret account status and the account service. If no account session exists, the process starts signed out. Supabase URL and publishable-key configuration can be supplied to `wd-core` through the existing flags/environment variables; when an existing session is present, its project URL and publishable key are used as defaults if explicit configuration is absent. The UI does not send project configuration over the account IPC methods.

The account service is also the credential-free authorization boundary used by the connection backend. It refreshes and persists the protected account session under its existing lock and returns only a short-lived connection grant or route authorization to networking code; access and refresh tokens remain inside the account service/session store.

`wd-core` uses `localserver.DefaultConfig`, so IPC connections inherit the shared concurrency bound, request timeout, panic isolation, active-request shutdown, and one-request-per-connection behavior. Interrupt cancellation closes the protected listener and drains active IPC requests. The process runtime then closes the connection service, which cancels any in-flight backend opens, discards retained terminal-stream handles, and tears down active authenticated sessions.

`wd-core` is still manually started in this milestone. It is not installed or autostarted.

## Account authentication

`account.sign_in` accepts only an email address and password. The core validates bounded input, requires configured Supabase project information, calls the existing account client, and persists the resulting account session before publishing signed-in status. If login or persistence fails, signed-in status is not published and backend error details are sanitized at the IPC boundary.

The account session remains inside the core and existing account-session storage. On Windows, access and refresh tokens are protected with the current user's DPAPI context before being written. On Unix-like systems, the existing store is a permission-protected JSON file that must not be accessible to group or other users (`0600`); it is not encrypted at rest by this layer.

`account.sign_out` treats local session removal as authoritative. The core attempts session refresh and remote logout on a best-effort basis, then removes the local protected session and clears observable signed-in status. A network outage or remote logout failure therefore does not trap the user in a locally signed-in state. A request that is already canceled before sign-out begins does not mutate the local session.

No account IPC response contains an access token, refresh token, password, or other credential. Successful sign-in/sign-out responses use the ordinary non-secret `Status` shape.

## Transport and route status

`internal/coreapi.NetworkReadService` implements the `TransportService` and `RouteService` read capabilities. It performs no discovery, dialing, reachability probing, grant issuance, route authorization, or route selection.

`transports.list` returns transport classes in deterministic order. In this API, `available` means that the transport class is implemented by the current core build and can be used by core networking logic; it does **not** mean that the Internet is reachable, that LAN discovery currently finds a peer, or that a specific destination can be contacted. The current build reports LAN and Internet support and reports Bluetooth as unavailable because Bluetooth transport is not implemented yet.

`route.get` accepts a Local Core connection ID and returns only non-secret path metadata. Path state is process-local and ephemeral; it is not written to disk. The connection manager publishes this state only after a backend reports that an authenticated application session has been established.

For routed connections, UI-visible hops are derived from the existing validated `mesh.Route` structure. The route must match the local source and requested destination and must still be unexpired before it can be published. Returned hop slices are copied so callers cannot mutate core state. When a route reaches its expiry, the stored status is removed and subsequent reads fail closed with `route_not_found`.

Non-routed `direct`, `lan`, and `relay` path snapshots contain no mesh-route hops, router ID, or route expiry. A non-routed snapshot that attempts to attach a mesh route is rejected.

Natural backend close is observable: when the authenticated session ends remotely, the connection manager removes the corresponding active connection and path snapshot immediately. A bounded terminal-output handle may remain briefly only so final PTY bytes can be drained; this retained handle does not restore or imply connected route state.

## Security boundary

The Local Core API must never return:

- device private keys
- TLS private keys
- Supabase access or refresh tokens
- account passwords
- connection-grant JWTs
- route-authorization signing keys
- relay authentication secrets
- raw transport/TLS error detail

The API may return non-secret identifiers such as device IDs, public-key fingerprints, route hops, selected path type, account email/user ID, and terminal output produced by the explicitly connected remote session.

Credential-bearing account input and terminal input are accepted only over the protected per-user IPC boundary. They must not be logged, copied into diagnostic errors, exposed through status, or forwarded to unrelated services.

## Connection semantics

A `Connect` request names only the destination device. The UI does not choose cryptographic grants, transport locators, routers, route costs, or authorization material.

`internal/coreapi.ConnectionService` is a bounded lifecycle manager around a `ConnectionBackend`. `internal/coreconnect.Backend` is the concrete security-sensitive implementation. It reuses the existing paired trust store, trusted LAN discovery and TLS probe, connection-grant issuance, relay proof-of-possession tickets, endpoint-pinned session TLS, and one-hop route authorization/dialer primitives.

For ordinary connections the backend preserves the existing path behavior. A trusted LAN advertisement may replace a relay locator only when its full fingerprint matches the paired identity and an endpoint-pinned TLS probe succeeds. Otherwise the paired direct/relay locator remains the fallback. Direct and legacy-relay sessions carry the short-lived terminal grant in-band. Serverless WebSocket relay sessions carry that same grant in the outer relay request and open the existing inner session without duplicating it in-band.

Routed authorization remains distinct from terminal authorization. The backend accepts only an internal `RouteRequestSource`; UI requests cannot provide routers or hops. When an internal policy source selects a route, the backend obtains the terminal grant first, requires the dedicated source-to-router trust store, requests the separate `mesh.forward` route authorization, validates its exact binding, and then uses the existing `meshnet.RoutedDialer`.

The default `wd-core` composition supplies `internal/coreconnect.PolicyRouteSource`. It reads the optional source-bound `route-selection.json` policy from the client state directory for each connection attempt. The policy never grants trust: a candidate router must independently exist in `trusted-route-routers.json`, terminal trust is not consulted for routing eligibility, and B/C continue to enforce their own directional route trust stores. If the file is absent, disabled, or has no eligible candidate for the requested destination, the existing non-routed LAN/direct/relay selection remains unchanged. A malformed enabled policy fails as a configuration error rather than being silently ignored.

For eligible candidates, the source chooses the lowest total configured one-hop cost using only `lan` or `internet`. Once an explicit policy selects a route, later route-authorization, resolver, trust, or network failure is returned instead of silently changing that operator decision into another path. The detailed file schema and failure semantics are defined in `docs/LOCAL_ROUTE_SELECTION.md`.

## Terminal stream semantics

`session.ManagedTerminal` establishes the same authorized terminal application session as the existing CLI. Local Core terminal operations are methods on that already-established handle; no terminal method can open a new network session or mint authorization material.

The v1 stream methods are:

```text
terminal.read
terminal.write
terminal.resize
```

All are addressed by the opaque connection ID returned from `connection.connect`.

The stream is deliberately pull-based over the existing one-request-per-IPC-connection protocol instead of keeping a privileged local socket open indefinitely. `terminal.read` returns binary terminal bytes as the normal JSON encoding of `[]byte` and a `closed` flag. When no bytes or remote-close signal arrive during the approximately one-second server-side long poll, it returns an empty result with `closed=false`; callers can immediately issue another bounded read. `terminal.write` accepts binary bytes for the remote PTY. `terminal.resize` updates PTY rows and columns.

Bounds and failure behavior are explicit:

- one read or write is at most 32 KiB;
- an idle read returns an empty still-open result after about one second, keeping it below the default five-second Local Core request deadline;
- unread output is capped at 256 KiB per managed terminal;
- if that output buffer would overflow, the authenticated terminal session is terminated rather than silently dropping output or allocating without bound;
- writes are serialized and bounded by request context plus an internal write deadline;
- reads are serialized so byte order is deterministic;
- resize dimensions must be non-zero;
- terminal methods fail closed for active connections whose backend handle is not terminal-capable;
- after a natural remote close, active connection/path state is removed immediately, but buffered final output may be read for up to 30 seconds;
- a completed final read removes the retained terminal handle immediately;
- retained closed handles are also capped relative to the active-connection limit;
- explicit `connection.disconnect` removes the terminal handle rather than retaining it, because the caller explicitly requested teardown;
- process shutdown discards all retained streams and closes active handles.

The manager still owns the lifecycle concerns around connections:

- it reserves capacity before an open begins so concurrent opens cannot bypass the active-connection limit;
- it creates opaque random connection IDs before opening network state and retries ID collisions rather than overwriting an existing connection or retained stream;
- request cancellation remains observable as cancellation rather than being converted into a generic backend failure;
- process shutdown actively cancels in-flight backend opens;
- only successfully authenticated backend results can publish UI-visible path state;
- invalid backend results fail closed and any returned handle is closed;
- disconnect removes UI-visible path state before closing the underlying handle;
- natural remote close removes the active connection and path state without exposing transport error detail;
- if a handle close fails, the connection remains internally retryable but its path state is not re-published;
- manager shutdown prevents new connects, removes all path state, closes active handles, and returns only sanitized aggregate failure information.

The selected public path remains one of:

```text
direct
lan
routed
relay
```

Active connection-manager and terminal-buffer state is process-local and is not persisted to disk.

## Router policy and statistics

Router administration is implemented as a proxy to the authoritative `wd-agent` routing runtime rather than a second policy registry in `wd-core`. The v1 surface exposes `router.policy.get`, `router.policy.set`, and `router.stats.get` only when a router service is explicitly composed.

The Local Core router service uses the separately authenticated machine-local router-admin channel described in `docs/LOCAL_ROUTER_SERVICE.md`. Unsupported policy fields fail closed, router participation remains explicit opt-in, and `Enabled` cannot create a route-control listener.

## Next slices

1. wire the Windows GUI prototype to the same `v1` service contract, including the bounded terminal methods;
2. exercise GUI/core lifecycle behavior under reconnect, upgrade, and process-restart cases;
3. decide installation/autostart behavior only after process lifecycle and upgrade behavior are explicitly designed and tested.

The existing CLI and staging-tested routed-terminal path remain the compatibility baseline throughout this work.
