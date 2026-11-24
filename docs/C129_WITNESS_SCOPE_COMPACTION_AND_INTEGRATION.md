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

### Local Core authorization bridge and production fail-closed behavior

Added `CheckpointAuthorizationReplay`, which implements the complete-capability replay interface used by Local Core. It rejects bare-JTI calls and, for a verified signed `Authorization`, derives the checkpoint request through `BuildCheckpointRequest`. That builder verifies the control-plane signature, exact JTI and digest, local endpoint identity, both membership records and revocation epochs, and routed authorization when applicable. It then consumes through a `WitnessedReplayCheckpointProvider`; there is no un-witnessed provider type accepted by this bridge.

Local Core now accepts an explicitly supplied witnessed provider, independently authenticated membership resolver, and optional route verifier. It copies the provider and installs its own protected durable pending journal under the Local Core state directory. It rejects the deprecated single-provider endpoint/API-key configuration and does not fall back to local replay files.

`NewProductionRemoteReplay` now rejects the legacy single-provider configuration. `NewRemoteReplay` and `NewPinnedRemoteReplay` remain available for controlled test/migration use; neither is a production witness adapter.

## Production integration still required

This repository change does not claim that the checkpoint protocol is deployed. The following engineering and infrastructure work is still required before production forwarding can be enabled:

1. Implement network adapters for the primary checkpoint service and each independent witness. Authenticate each endpoint with TLS 1.3, separately provisioned hostname and SPKI pins, and distinct Ed25519 signing keys.
2. Implement production network adapters for the primary checkpoint service and each independent witness, then inject the `WitnessedReplayCheckpointProvider` and production membership resolver into Local Core startup. The in-process adapter and provider interface are wired; no network provider adapters are currently available.
3. Supply a production membership resolver that independently authenticates both endpoint membership records and current revocation epochs, and a route-authority verifier for routed capabilities. Do not infer membership from the local account session alone.
4. Make membership and revocation validation atomic with primary consumption, or bind the membership version/revocation epochs into the checkpoint transaction so concurrent revocation cannot race the consume.
5. Ensure the source and destination Local Core instances use the same canonical request fingerprint and the correct endpoint identity.
6. Run real service integration tests for primary and witness restart, response loss, ambiguous commit, concurrent revocation, quorum partition, historical-head restore, and full provider database plus signing-key restore.
7. Provision at least three separately administered witness instances, independent KMS/HSM keys, separate backup and administrative controls, independent audit retention, TLS hostnames and SPKI pins. Test the actual restoration and compromise boundaries with the operators who control those services.

Until those steps are complete, production forwarding remains unavailable by design. Deterministic in-memory witnesses are protocol test fixtures only and do not demonstrate provider independence or real rollback resistance.

## Verification status

The exact final branch SHA and CI workflow results must be recorded in the C129 handoff after CI completes. No production signing, deployment, PR merge, or real-infrastructure acceptance is part of this change.
