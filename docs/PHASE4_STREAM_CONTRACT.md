# Phase 4 multiplexed stream contract

This document defines the security and protocol requirements for Phase 4 multi-stream, file-transfer, and port-forwarding work. Terminal multiplexing is implemented; the file-transfer and forwarding sections remain design gates for work that is not yet enabled.

## Current state

Terminal multiplexing is implemented over the existing authenticated parent TLS/session boundary:

- `typed-streams-v1` is an explicitly negotiated optional capability; legacy peers retain the existing stream-1 terminal behavior;
- typed stream IDs begin at `2`, are unique for the parent connection lifetime, and are never renderer-visible wire identifiers;
- one authenticated parent may own a bounded set of independently flow-controlled terminal children, each with its own PTY, input/output, resize, and close lifecycle;
- Local Core owns opaque `term_...` identifiers and the mapping to wire stream IDs;
- desktop tabs for the same device reuse one Core-owned authenticated parent when multiplexing is negotiated, while legacy peers remain limited to the existing default terminal;
- child close is acknowledged and does not close siblings; parent loss closes every child;
- malformed or out-of-order typed controls fail closed, concurrent/lifetime stream allocation is bounded, and stream lifecycle audit records include the authenticated peer/transport plus numeric wire `stream_id`;
- pinned TLS identity, connection authorization, route/transport selection, and trust remain parent-connection responsibilities and are not delegated to logical children or the renderer.

File transfer and local/remote port forwarding are not enabled yet. They require their own negotiated capabilities, operation authorization, resource policy, audit semantics, and narrow Local Core APIs before UI exposure.

## Non-negotiable security boundary

Multiplexing must not change identity, trust, or transport semantics.

- TLS 1.3 with the existing pinned Ed25519 device identity remains the authenticated transport boundary.
- `wd-agent` remains authoritative for accepted operations, process/file/network access, limits, and audit records.
- Local Core remains the UI-facing connection/stream authority.
- The renderer never receives private keys, pairing secrets, connection grants, raw trust stores, or transport endpoints merely to operate a stream.
- Bluetooth/USB/LAN/relay metadata remains routing information only and never becomes authorization evidence.
- Explicit transport selection remains fail-closed with no fallback.
- Router administration remains a separate local administrative trust domain.

## Protocol direction

Do not repurpose existing v1 frame meanings in-place. A peer that understands only the existing single-terminal contract must fail closed rather than interpret a new stream type as terminal data.

Terminal multiplexing uses the explicitly negotiated `typed-streams-v1` capability. Compatibility tests prove that:

1. old peers continue to interoperate for the existing terminal-only behavior;
2. a new client never sends multiplex-only terminal messages to a peer that did not negotiate them;
3. a new server rejects malformed, duplicate, out-of-order, or unauthorized typed terminal operations;
4. unknown stream kinds and unknown control messages fail closed.

Future operation families must negotiate their own capability in addition to the typed-stream framing they use. In particular, successful negotiation of `typed-streams-v1` alone must not imply that a peer authorizes or understands file transfer or port forwarding.

## Stream model

A multiplex-capable secure connection owns a bounded set of independently identified logical streams.

Each stream has:

- a non-zero `StreamID` unique for the lifetime of the secure connection;
- an explicit stream kind;
- a lifecycle of `opening -> open -> closing -> closed`;
- operation-specific limits and authorization;
- independent flow-control/backpressure accounting;
- an audit identity tying it to the authenticated peer and parent secure connection.

Stream kinds are explicit protocol constants rather than free-form renderer strings. Terminal is implemented. Future reviewed kinds may include:

- file upload
- file download
- local-forward data
- remote-forward data

The renderer must never be able to invent an unrecognized stream kind that the Core/agent silently accepts.

## Connection versus operation authorization

Authentication of the TLS connection is necessary but not sufficient for privileged operations.

The existing connection authorization path remains the gate for establishing the authenticated secure connection. New operation types must then have explicit authorization semantics before implementation.

At minimum:

- terminal access retains the current paired-client and connection-authorization requirements;
- file transfer must be separately policy-controllable from terminal access;
- port forwarding must be separately policy-controllable from terminal access and file transfer;
- remote forwarding/listening must be distinguishable from outbound/local forwarding because its exposure and risk are different;
- routed sessions must carry equivalent operation authorization end to end and may not gain privileges from router trust.

Do not infer file-transfer or forwarding permission from successful terminal authorization unless a reviewed policy explicitly defines that equivalence.

## Resource bounds

All multiplexed operations must be bounded before they reach a renderer API.

The implementation must define and test:

- maximum simultaneous streams per secure connection;
- maximum aggregate streams per client/device;
- maximum frame payload and per-stream chunk size;
- maximum buffered unread bytes per stream and per secure connection;
- write deadlines and cancellation behavior;
- idle timeout and maximum duration where applicable;
- deterministic behavior when a consumer stops reading;
- cleanup on parent connection loss.

A slow or abandoned stream must not create unbounded memory growth or block unrelated streams indefinitely.

## Terminal streams

Multiplexed terminal streams are implemented and gated by `typed-streams-v1`.

Implemented properties:

- each accepted terminal stream starts exactly one PTY;
- input/output/resize/close messages identify the target stream;
- one stream closing does not implicitly close sibling streams;
- parent TLS failure closes every child stream;
- per-stream output queues are bounded;
- stream-ID reuse within one secure connection is rejected;
- terminal stream authorization remains anchored to the authenticated parent connection;
- audit events identify the authenticated peer/parent transport and numeric child stream ID;
- the desktop receives only opaque Core-issued terminal IDs and cannot select wire stream IDs or bypass parent authorization.

Live pinned-TLS regression coverage proves independent sibling I/O and resize, acknowledged child close with sibling survival, parent cleanup, malformed-frame failure, and resource limits across the normal managed client/server path.

## File transfer

File transfer should be a purpose-built operation, not terminal command injection or an implicit shared filesystem API.

Required design properties:

- explicit upload versus download direction;
- sanitized, bounded metadata messages separated from file byte chunks;
- no absolute-path trust from the renderer;
- server-side path policy/canonicalization and symlink handling defined before writes;
- configurable size limits;
- optional expected size and cryptographic digest checked before final commit;
- upload writes staged privately and atomically committed only after successful validation;
- cancellation removes partial temporary files;
- existing destination overwrite behavior is explicit and fail-closed by default;
- download reads are bounded and policy checked before opening the file;
- audit records do not log file contents or secrets.

The desktop must not expose arbitrary agent filesystem authority until this server-side policy exists.

## Port forwarding

Port forwarding should use explicit stream/control messages and Core-owned listeners/dials, never renderer-created sockets that bypass Core policy.

Required design properties:

- separate local-forward and remote-forward operations;
- explicit address-family, host, and port validation;
- default bind scope is loopback for local listeners unless policy explicitly permits broader exposure;
- remote listening is disabled unless separately authorized;
- privileged ports, wildcard binds, Unix sockets, and non-TCP forwarding require explicit support rather than accidental acceptance;
- each accepted forwarded connection receives a bounded logical data stream;
- connection counts, bandwidth, idle time, and lifetime are bounded;
- DNS resolution semantics and rebinding behavior are defined at the authoritative side;
- forwarding may not create a router-admin path or bypass routing policy;
- audit records capture operation, endpoints at the appropriate privacy level, outcome, and reason without payload contents.

## Local Core API direction

Renderer APIs remain typed and narrow. Terminal stream open/close/read/write/resize is implemented through opaque Core-owned terminal IDs. Candidate future Core-level operations are conceptually:

- begin/read/write/cancel file transfer;
- start/stop/list local forwards;
- start/stop/list remote forwards.

Exact API types should be added only with the corresponding agent/session implementation so a UI method cannot imply a security guarantee the runtime does not yet enforce.

## Desktop profiles

Session profiles are presentation/connection preferences only. They may contain non-secret preferences such as:

- profile label;
- target device ID;
- terminal dimensions/presentation defaults when supported;
- user-facing reconnect preference when that behavior has explicit Core semantics.

Profiles must never persist private keys, account tokens, pairing secrets, connection grants, authoritative fingerprints copied from discovery, or raw transport endpoints as a substitute for Core-owned device state.

## Completion gates

A Phase 4 feature is not complete because UI controls exist.

For multiplexed terminals, file transfer, or forwarding, completion requires:

1. explicit protocol/Core/agent contract;
2. authorization policy and negative tests;
3. bounded resources and cancellation/cleanup tests;
4. direct and routed-path tests where the operation is supported;
5. compatibility tests against peers without the new capability;
6. desktop integration through the narrow Local Core boundary;
7. canonical CI on supported platforms;
8. no fallback or trust-boundary regression.

Hardware-only Phase 3 evidence remains separate from these repository-side Phase 4 gates.
