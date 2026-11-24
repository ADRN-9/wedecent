# C129 — witness scope, pending journal compaction, and production integration

## Implemented in this change

### Exact witness scope binding

A witness head is accepted only when its authenticated `Scope` exactly equals the scope requested from the witness. Both the public `Head` path and consume preflight enforce equality of device ID, account ID, and organization ID after signature verification. A correctly signed head for another scope is therefore not counted toward quorum.

The regression harness signs deliberately mismatched heads (rather than corrupting signatures) for each scope dimension. It also exercises a mixed quorum where two of three witnesses return validly signed but out-of-scope heads; the single in-scope response cannot satisfy quorum.

### Bounded pending journal and acknowledgement-backed compaction

The durable journal now has a 16 MiB size ceiling and a 65,536-entry ceiling. It rejects new operations when the entry bound is reached rather than allowing unbounded growth. Every successful witnessed operation must produce independently signed acknowledgements from quorum before compaction is attempted.

Compaction removes only `resolved` entries for which a quorum of distinct configured witness keys has signed acknowledgements matching all of:
- device, account, organization, and JTI journal key;
- exact request fingerprint;
- exact primary receipt digest;
- acknowledgement status `acknowledged`.

Unresolved entries are never removed. Invalid signatures, duplicate witness IDs, mismatched scopes, wrong fingerprints, wrong receipt hashes, and `already_acknowledged` receipts do not establish compaction eligibility. The memory implementation is test-only. A journal that cannot safely compact eventually fails closed at its configured bound.

After compaction, a replay is still rejected by the primary replay authority and independently retained witness state. Local journal deletion is not treated as proof of replay completion.

### Production authorization path: deliberately fail closed

The current Local Core production path composes `AuthorizationVerifier` with the legacy single-provider `RemoteReplay`. That API accepts a complete signed forwarding capability, but it does not implement the C128 `ReplayCheckpointProvider` protocol, witness quorum, signed witness heads, or witness acknowledgements. It cannot be represented as independently witnessed production replay.

Accordingly, `NewProductionRemoteReplay` now rejects the unwitnessed single-provider configuration. Local Core therefore refuses to start forwarding with that path rather than silently falling back to the single-provider authority, local replay files, or the test-only deterministic witness provider. `NewRemoteReplay` and `NewPinnedRemoteReplay` remain available for controlled test/migration use; neither is a production witness adapter.

## Production integration still required

This repository change does not claim that the checkpoint protocol is deployed. The following engineering and infrastructure work is still required before production forwarding can be enabled:

1. Implement network adapters for the primary checkpoint service and each independent witness. Authenticate each endpoint with TLS 1.3, separately provisioned hostname and SPKI pins, and distinct Ed25519 signing keys.
2. Extend Local Core configuration with an explicit production `ReplayCheckpointProvider`, independently authenticated witness trust set, and a `CheckpointPendingStore`. Reject missing or duplicate witness identities, duplicate signing keys, a witness key reused as the primary key, and a quorum that is not a strict majority.
3. Implement the Local Core adapter from the exact control-plane-verified `Authorization` to `BuildCheckpointRequest`. The adapter must obtain both endpoint memberships and current revocation epochs from an independently authenticated membership resolver, verify routed authorization with the route authority, and derive JTI/digest/endpoints from that same capability.
4. Make membership and revocation validation atomic with primary consumption, or bind the membership version/revocation epochs into the checkpoint transaction so concurrent revocation cannot race the consume.
5. Ensure the source and destination Local Core instances use the same canonical request fingerprint and the correct endpoint identity. Do not infer membership from the local account session alone.
6. Run real service integration tests for primary and witness restart, response loss, ambiguous commit, concurrent revocation, quorum partition, historical-head restore, and full provider database plus signing-key restore.
7. Provision at least three separately administered witness instances, independent KMS/HSM keys, separate backup and administrative controls, independent audit retention, TLS hostnames and SPKI pins. Test the actual restoration and compromise boundaries with the operators who control those services.

Until those steps are complete, production forwarding remains unavailable by design. Deterministic in-memory witnesses are protocol test fixtures only and do not demonstrate provider independence or real rollback resistance.

## Verification status

The exact final branch SHA and CI workflow results must be recorded in the C129 handoff after CI completes. No production signing, deployment, PR merge, or real-infrastructure acceptance is part of this change.
