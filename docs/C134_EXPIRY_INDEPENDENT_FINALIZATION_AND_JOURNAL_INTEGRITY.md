# C134 — Expiry-independent checkpoint finalization and journal integrity

## Scope

This change separates recovery of an already-consumed forwarding capability from normal authorization consumption. It does not relax normal authorization expiry or provide a new session grant.

## Finalization path

- The pending journal now records the exact device-signed `CheckpointRequest` and, after local resolution, the authenticated primary `CheckpointReceipt`.
- `CheckpointAuthorizationReplay.FinalizeExpiredPortForwardAuthorization` validates the original control-plane signature and capability digest without treating expiry as permission to consume again. It locates only the exact local-device/JTI/digest journal operation and verifies the persisted device signature.
- `WitnessedReplayCheckpointProvider.Finalize` uses the journal request and a read-only `ReplayCheckpointRecoveryProvider.Recover` operation when the receipt was not durably copied locally. It never calls primary `Consume` or witness `Commit`.
- It recovers missing witness acknowledgements only. A quorum of valid acknowledgement responses is required before compaction; no checkpoint result or session authorization is returned.
- A primary-only operation with no witness commitment fails closed with quorum/ambiguous recovery errors. The deterministic provider implements the read-only recovery interface for tests.

## Journal schema and validation

The pending journal schema is version 2. Version 2 persists request and receipt material in addition to the request fingerprint, state, receipt digest and acknowledgement records. Version 1 journals are rejected rather than silently reset or guessed at; operators must retain the original file and perform explicit recovery/migration before deploying this schema.

Every file-store read-modify-write validates all entries, including entries unrelated to the current operation. Checks include canonical request fingerprint, exact composite key, positive bounded creation timestamp, supported state, pending/resolved evidence consistency, receipt digest and request binding, acknowledgement scope/JTI/fingerprint/receipt binding, acknowledgement status, and duplicate witness IDs. A recursive JSON token scan rejects duplicate object keys at any nesting depth. The durable store enforces its configured byte and entry bounds before publication.

Acknowledgement signatures are verified against witness trust anchors when the exact operation's acknowledgements are loaded and before compaction. The current journal-wide structural validation does not yet have an injected immutable trust-anchor set for cryptographically re-verifying every acknowledgement in every unrelated entry; this remains a hardening item.

## Verification added

- Finalization after the authorization's expiry following witness commitment and an injected local-resolution failure.
- Primary-only ambiguous operation cannot be finalized and does not trigger witness commitment.
- Full top-level `Consume` restart recovery after lost acknowledgement responses, including authenticated `already_acknowledged`.
- Durable byte-size and entry-exhaustion checks.
- Nested duplicate JSON key rejection and corruption in an unrelated entry.
- Interrupted journal publication leaves the previously published bytes intact.

## Explicit remaining gaps

1. The production primary checkpoint adapter does not yet implement the new read-only `ReplayCheckpointRecoveryProvider` interface. Production expiry-independent finalization therefore fails closed with `ErrCheckpointAmbiguous` until that authenticated recovery endpoint is implemented and deployed.
2. Production independent witness network adapters, TLS 1.3 exact hostname/SPKI pinning for those adapters, live membership/revocation authority and provider rollback acceptance remain unimplemented/unevidenced here.
3. The new fault hook verifies preservation when publication fails as a whole. Stage-specific process-crash injection at temporary creation, partial write, file sync, close, atomic replacement, directory sync and lock release remains incomplete.
4. Multi-process concurrent finalization and independent provider-instance stress against real shared primary/witness authorities remain unverified.
5. Journal-wide cryptographic acknowledgement verification against configured witness trust anchors remains incomplete as described above.
6. Cross-platform CI, all three Desktop checks, and production infrastructure acceptance must pass before any security or release acceptance.

This document records engineering status only. It is not an independent security acceptance or production-readiness claim.
