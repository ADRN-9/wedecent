# Persistent audit events

WeDecent role state directories may contain an append-only `audit.jsonl` security-event log. Each line is one JSON object with a UTC timestamp, stable event type, outcome, and a deliberately small set of identifiers/reason fields.

The audit schema intentionally has no arbitrary payload field. Terminal input/output, pairing secrets, connection grants/JWTs, passwords, access/refresh tokens, private keys, and other credential material must never be written to this log.

## Storage and bounds

- active log: `<role-state>/audit.jsonl`
- one rotated archive: `<role-state>/audit.jsonl.1`
- active and archive files are secured to mode `0600` where the platform supports POSIX-style mode bits
- the role state directory is created with mode `0700`
- append operations are serialized across processes with an OS-backed lock file
- the active log rotates at 16 MiB; only one archive is retained, bounding audit-log storage to roughly 32 MiB plus one small lock file
- each encoded event is limited to 4 KiB
- symbolic-link or non-regular-file log/lock/archive paths are rejected
- each successful append is flushed with `fsync`/the platform equivalent before returning

Rotation is local operational retention, not tamper evidence. A local account with permission to modify the role state directory can alter or delete local audit files. Central immutable audit retention remains a separate team-control-plane concern.

## Event set

Local trust administration records:

- `trust.device_unpair` — client-side removal of a trusted device
- `trust.client_revoke` — agent-side removal of a trusted terminal client
- `router.controller_trust` — local router-controller trust addition or explicit key replacement
- `router.controller_revoke` — local router-controller trust removal

Trust mutation commands persist an `attempt` event before changing the trust store, then append `success` or a stable `denied`/`failed` reason. If the initial audit append fails, the trust mutation is not attempted. If the trust mutation succeeds but the final success event cannot be persisted, the command returns an explicit error describing that the state change already occurred. Router-controller fingerprints are never copied into the audit log.

Agent pairing and terminal lifecycle records:

- `pairing.request` — denied or failed pairing attempts using stable reason codes only
- `pairing.trust_added` — successful client trust creation after the single-use pairing secret has been consumed
- `terminal.authorization` — direct-session authorization success or denial; grants and authorization-service error strings are never recorded
- `terminal.session_opened` — successful, denied, or failed terminal-open attempts
- `terminal.session_closed` — the end of an accepted terminal session with a stable close reason such as `process_exit`, `peer_close`, or `peer_disconnect`

Router administration records:

- `router.policy_set` — authenticated router-policy mutation attempts and their success/failure result. `actor_id` is derived from the already-authenticated controller certificate and `peer_id` identifies the agent whose authoritative runtime is being changed. Policy request payloads are intentionally not copied into the audit record.

Runtime pairing/session audit writes are best-effort after the security decision: an audit I/O failure is emitted to the normal operator log but does not tear down an already-authorized terminal session. Router policy and explicit trust mutation attempts are fail-closed if the pre-mutation audit record cannot be persisted; result-event failures are warned without silently undoing a mutation that may already have committed.
