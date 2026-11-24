# C139 — witness revocation fencing and distributed authorization findings

## Exact starting revision

- PR: #186, `feat/secure-port-forwarding-foundation`
- Branch-resolved revision inspected before edits: `14d5522b633a41b75dd2c0c367a5c127edb3c1a9`
- This was independently fetched from the PR branch reference; it supersedes the earlier report's `be7f3d49...` snapshot.

## Implemented in C139

The deterministic witness implementation now treats its mutex-protected membership check as the local ordering point between witness `Commit`, `Acknowledge`, and `Revoke`.

- Witness `Commit` checks the signed initiator and destination epochs and also the signed router epoch whenever the request carries the routed authorization fingerprint.
- Witness `Acknowledge` repeats the same complete participant-vector check. A receipt committed before revocation cannot receive a new acknowledgement after any endpoint or router is revoked.
- The participant vector is derived from the device-signed `CheckpointRequest`; the existing request fingerprint validates the route-fingerprint/router-presence pairing and signs the router's device, account, organization and revocation epoch. No transport or route metadata is substituted for identity.
- Witness heads report the monotonic revocation epoch even when no replay ledger exists yet; an existing ledger whose epoch disagrees with the witness revocation map fails closed.
- Before persisted acknowledgements are reused, the provider rechecks signed initiator, destination and router epochs against primary and witness heads. It repeats this check immediately before the finalization audit callback. This narrows stale-ack reuse but is explicitly not a distributed atomic finalize/revoke transaction.
- Stale epoch values fail with `ErrCheckpointRevoked`; missing or malformed route/router bindings fail through the existing checkpoint request integrity validation.

New deterministic regression coverage includes:
- Commit rejected after initiator revocation.
- Commit rejected after destination revocation.
- Commit rejected after router revocation.
- Acknowledgement rejected after each of those three revocations.
- Concurrent commit/revoke, with acknowledgement fenced after successful revocation.
- Concurrent acknowledgement/revoke, with any later acknowledgement fenced.
- Concurrent primary consume/revoke, proving a primary receipt cannot subsequently be committed by a witness after router revocation.
- Persisted acknowledgement reuse rejected after subsequent initiator, destination or router revocation.
- Deterministic primary fixture now requires the signed router membership to exist and match exactly for routed consumption.

## Distributed-ordering boundary

This change closes the missing router/endpoint epoch checks in the repository's deterministic witness adapter. It does **not** establish distributed atomicity across production primary and independently operated witness services.

The mutex is only the deterministic witness fixture's local serialization mechanism. Production adapters must implement durable compare-and-set/transactional epoch checks in the same witness authority transaction that records Commit or Acknowledge. Revocation must update that same authority's monotonic membership fence. A production acknowledgement must reject any participant vector whose current epoch differs from the signed request, even if an earlier witness receipt exists.

The current repository documents that production primary recovery, independent witness network adapters, and authoritative membership resolution are not yet implemented or provisioned. No deterministic fixture is represented as a production adapter.

## Supabase transaction investigation

The inspected `supabase/functions/port-forward-replay/index.ts` currently resolves only the submitted `device_id`, checks `public_key` and `revoked_at`, verifies that one device's Ed25519 proof, and invokes the replay RPC with only device ID, JTI, expiry and authorization digest.

The inspected `consume_port_forward_authorization` SQL function locks only that device row and one per-device replay-authority row. It does not accept or atomically validate initiator, destination and router membership, their account/organization bindings, their revocation epochs, or device-access permissions. The current pgTAP test seeds `devices.owner_user_id` but does not demonstrate an authoritative organization/device-group membership schema for this transaction.

C139 therefore does not invent table names, permission semantics, or migration dependencies. A correct expanded transaction requires the canonical schema and authorization contract for organization membership, device groups/access grants and revocation epochs. Those authoritative records must be locked in a deterministic order (stable device IDs and stable membership keys), validated in one SQL transaction, and the JTI inserted only after every participant and permission check succeeds. The Edge Function must pass the exact signed capability participant vector and the SQL function must independently validate it; Edge Function pre-reads are not an atomic substitute.

## Not completed / acceptance blockers

- No production primary or independent witness adapters are present in the inspected PR tree.
- No production membership/revocation resolver or trusted membership schema contract was available to safely implement the expanded SQL transaction.
- No real primary/witness distributed prepare/finalize protocol was implemented.
- No production credentials, service endpoints, TLS SPKI pins, KMS/HSM trust anchors, or independent witness infrastructure were provisioned.
- No local Go toolchain/repository checkout was available in this execution environment; validation was performed through GitHub Actions rather than a claimed local test run.

## Exact-HEAD verification

Code/test HEAD: `75301b8ea45a726ec64b86f47a919f187463c04b`.

- CI workflow [45334093686](https://github.com/ADRN-9/wedecent/actions/runs/45334093686) completed successfully at that exact code/test SHA. Linux formatting, replay stress/crash recovery, port-forward tests, port-forward race tests, all Go packages, vet, Unix packaging, protocol compatibility, fuzzing, full race suite, direct transport and relay smoke tests passed. Windows native tests/build, Windows release, macOS native tests/build, Supabase database, control-plane, relay worker, route capability client and routed E2E passed.
- Desktop workflow [45334093589](https://github.com/ADRN-9/wedecent/actions/runs/45334093589) was still running at the time of this document update: macOS Tauri passed; Linux prerequisite installation and Windows Tauri compilation were still in progress. No complete Desktop pass is claimed.
- An earlier CI attempt exposed formatting differences and routed fixture omissions; both were corrected before the successful exact-SHA run above.

The branch was confirmed identical to code/test HEAD `75301b8...` before this documentation-only update. PR #186 remains open and draft.

PR #186 must remain open and draft. This document records repository changes and blockers, not production readiness.
