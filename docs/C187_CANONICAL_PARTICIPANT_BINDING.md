# C187-D1 — canonical participant binding and historical transition

Starting HEAD: `1c10f675f21ee37899aeeb3c9010227e82344d0f`. PR #186 remains open/draft/unmerged; PR #176 remains independently open/draft/unmerged.

The Go event API no longer accepts a caller-provided participant digest. It receives participant records and derives the digest after validation. Canonical bytes are a domain tag plus NUL, u32be count, then records sorted by device ID: length-prefixed UTF-8 device/account/organization identifiers, u64be revocation epoch, u64be current head generation, and the exact 32-byte current head hash.

Validation rejects empty vectors, malformed IDs, duplicate devices, mixed organizations, bigint overflow and inconsistent generation/hash pairs. Device-scoped event scope must match an exact participant tuple. Membership, epochs and head state are digest-bound.

`ValidateCheckpointV1ToV2Transition` compares claimed participants against observed v1 heads exactly. Missing, stale, substituted or duplicate heads fail closed. The first v2 event binds exact historical generation/hash values; no old hash is rewritten and no generation reset is permitted. The next per-device generation must be old generation plus one, with overflow rejected.

The Go comparison is not a DB lock. Production must lock all existing `port_forward_replay_authority` rows in deterministic device order, compare the complete vector under lock, then perform the first v2 write in the same transaction. The SQL comparator is pure and accepts authoritative-locked-head data supplied by the caller. No second writer is activated.

Go tests cover ordering, membership/device/account/organization/epoch/head changes, duplicate/missing/malformed participants, stale/substituted/missing v1 heads, UTF-8 byte lengths, malformed digest parsing and overflow. Go reads the SQL pgTAP fixture and checks the shared event encoding, hash and participant digest. SQL pgTAP tests the same vector and exact/stale/substituted historical-head comparisons.

These tests establish encoding and comparison only, not atomicity, writer exclusion or independent witness consensus.
