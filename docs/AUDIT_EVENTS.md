# Persistent audit events

WeDecent role state directories may contain an append-only `audit.jsonl` security-event log. Each line is one JSON object with a UTC timestamp, stable event type, outcome, and a deliberately small set of identifiers/reason fields.

The audit schema intentionally has no arbitrary payload field. Terminal input/output, pairing secrets, connection grants/JWTs, passwords, access/refresh tokens, private keys, and other credential material must never be written to this log. Typed terminal lifecycle events may include the bounded numeric protocol `stream_id`; they never include terminal contents or renderer-local identifiers.

## Transport attribution

New agent terminal/pairing audit records use explicit, validated metadata supplied by the local listener or transport adapter. The `transport` field uses these canonical values:

- `direct_tcp` — direct TCP listener.
- `bluetooth_rfcomm` — Bluetooth Classic RFCOMM listener.
- `usb_cdc_acm` — explicitly configured USB CDC-ACM serial stream.
- `raw_relay` — raw TCP relay stream; the target consumes the grant through its approved authorization origin.
- `websocket_relay` — authenticated WebSocket relay stream; the Worker consumes the grant during stream admission.
- `direct_tcp+usb_ncm` — direct TCP whose underlying link was explicitly identified as USB NCM.

For an agent TCP listener on an explicitly configured USB NCM link, set `--direct-tcp-underlay usb_ncm` (or JSON config key `direct_tcp_underlay`). The default is empty and records `direct_tcp`. The audit record also carries `transport_provenance`: `listener_adapter` for adapter-selected transports and `operator_config_assertion` for `direct_tcp+usb_ncm`. The latter is an operator assertion only; the agent does not independently attest the USB interface or route.

USB NCM is an underlying network medium, not a separate WeDecent identity or authorization transport. An unsupported or inconsistent metadata tuple closes the connection before TLS/session processing. The metadata is used only for audit attribution; it is never consulted for device identity, fingerprint pinning, trust, connection grants, routing authority, or authorization. IP addresses, Bluetooth MAC addresses, tty paths, USB descriptors, and relay state remain locators or diagnostics only.

Older terminal audit records may contain historical labels such as `direct` or `relay`; new relay records distinguish `raw_relay` from `websocket_relay` using trusted server-side ingress metadata. Route-control/tunnel events may separately use route labels such as `lan` or `internet`. These values are not reinterpreted as terminal transport metadata.

## Storage and bounds

- active log: `<role-state>/audit.jsonl`
- one rotated archive: `audit.jsonl.1`
- active and archive files are secured to mode `0600` where the platform supports POSIX-style mode bits
- the role state directory is created with mode `0700`
- append operations are serialized across processes with an OS-backed lock file
- the active log rotates at 16 MiB; only one archive is retained, bounding audit-log storage to roughly 32 MiB plus one small lock file
- each encoded event is limited to 4 KiB
- symbolic-link or non-regular-file log/lock/archive paths are rejected
- each successful append is flushed with `fsync`/the platform equivalent before returning

Rotation is local operational retention, not tamper evidence. A local account with permission to modify the role state directory can alter or delete local audit files. Central immutable audit retention remains a separate team-control-plane concern.

## Durable pairing completion and operator recovery

Agent pairing additionally maintains a separate protected `pairing-outcomes.json` recovery register, independently of rotating `audit.jsonl` and `audit.jsonl.1`. It contains a random attempt ID, exact actor/client identity and fingerprint, trust outcome, and—only after independently checking a synchronized completion event—a retained `audit_proof` copy of that event. The recovery register is written through a synchronized temporary file, atomic replacement, and directory synchronization, and has a strict bound of **64 records / 64 KiB**. Ordinary terminal events rotate only the audit logs; they do not rotate or evict the pairing register.

A successful trust commit is **not** itself evidence that the completion audit append succeeded. If the append fails, the client still receives the truthful pairing-success response while the recovery register remains successful with **no completion audit proof**. Restart and multiple audit rotations must not automatically convert that state into audited completion. An operator may acknowledge a success/denial only after the ledger contains an independently verified durable completion event. Acknowledgment stores a timestamp but **never deletes the proof or frees a record slot**. Older recovery entries without the new proof remain valid for reading, but cannot be acknowledged without independently authorized reconciliation. An unreadable, malformed, foreign-owned, truncated, replaced or missing initialized ledger blocks new pairings rather than being rebuilt or silently cleared.

When the original completion event has rotated away, `ReconcilePrivileged` is an explicit local **root or elevated Windows Administrator** operation, not a background heuristic. It independently reads the authoritative private trust store, compares the exact recorded client ID and fingerprint, writes a separate durable `pairing.reconciliation` event with `privileged_trust_review` reason, verifies that event, and stores a durable copy in the register. It is limited to outcome=`success`; pending, failed, denied or durability-uncertain trust must not be converted to success by observing a readable record. Credentials, pairing secrets and terminal data are never included.

**Capacity and administrative repair:** Once 64 records are present, even if some are acknowledged, subsequent valid pairing attempts fail closed before consuming their secret. Ordinary `AcknowledgeResolved` is not an eviction or garbage collection method. A separate, explicitly approved offline archival/migration procedure is required to reclaim space: stop the service, preserve a secure and independently verifiable copy of the entire register, its initialized lock marker, trust and consumed-secret state, and any remaining audit logs; conduct privileged review; obtain authorization for evidence retention and state migration/re-enrollment before replacement. There is no automated safe export/compaction CLI yet. **Do not delete, truncate, edit, or reset the register/lock simply to bypass capacity.** Full lifetime retention in the local 64-record register is an intentional availability limitation until an independently reviewed immutable archival workflow exists.

These guarantees concern process termination, filesystem error detection, and synchronization APIs. They do not independently demonstrate physical sudden-power-loss durability; Windows NTFS write-through behavior and actual service-account ACL integration still require native privileged review and testing.

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
- `terminal.session_closed` — the end of an accepted terminal session with a stable close reason such as `process_exit`, `peer_close`, `peer_disconnect`, `pty_drain_timeout`, `policy_idle_timeout`, or `policy_max_duration`
- `terminal.stream_opened` — a negotiated typed terminal child was accepted by the authoritative agent; the event includes the authenticated peer, parent transport, and numeric `stream_id`
- `terminal.stream_closed` — an accepted typed terminal child ended; the event carries the same peer/transport/`stream_id` identity plus a stable reason such as `peer_close`, `process_exit`, `pty_drain_timeout`, a stable stream error code, or the parent-session close reason

Typed stream lifecycle accounting is exact-once per accepted child. A stream rejected before `StreamAccepted` is not recorded as opened. Parent TLS/session termination accounts for every still-open typed child before the parent `terminal.session_closed` record. The wire stream ID is only an audit correlation identifier within that authenticated parent session; it is not identity or authorization evidence.

`pty_drain_timeout` means the child process exited but final PTY output did not finish draining within the bounded shutdown window. The server closes the transport without sending a terminal close frame so a close frame cannot overtake final terminal output.

Terminal timeout policy records only the stable close reason. The configured duration and all terminal input/output remain outside the audit payload.

Router administration records:

- `router.policy_set` — authenticated router-policy mutation attempts and their success/failure result. `actor_id` is derived from the already-authenticated controller certificate and `peer_id` identifies the agent whose authoritative runtime is being changed. Policy request payloads are intentionally not copied into the audit record.

Runtime pairing/session audit writes are best-effort after the security decision: an audit I/O failure is emitted to the normal operator log but does not tear down an already-authorized terminal session. Router policy and explicit trust mutation attempts are fail-closed if the pre-mutation audit record cannot be persisted; result-event failures are warned without silently undoing a mutation that may already have committed.

## Tenant control-plane audit

The database-backed, tenant-scoped security-audit foundation is documented in [TENANT_AUDIT_EVENTS.md](TENANT_AUDIT_EVENTS.md). It complements this local role-state event log; it does not replace local terminal lifecycle auditing or provide the separate tenant session-history API.
