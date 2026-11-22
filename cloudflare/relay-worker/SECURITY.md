# Relay admission and rate-limiter security

This document describes the relay-worker admission controls introduced by the bounded rate-limiter remediation.

## Cardinality and fairness

The centralized `ConnectionRateLimiter` Durable Object keeps a hard maximum of 4,096 identity buckets per scope. When an identity scope reaches that limit:

- Existing IP/device buckets continue to enforce their individual token buckets.
- A previously unseen identity does not allocate another persistent bucket.
- The request continues to the already-enforced global stream/direct quota.
- If the global quota is exhausted, the request is rejected without committing a new identity bucket.
- Expired identity buckets are reclaimed by request-time expiry checks and the Durable Object alarm.

Bucket writes are staged and committed only after every applicable bucket accepts the request. A request rejected by a later global bucket therefore cannot leave a newly allocated IP/device bucket behind.

The overflow path intentionally trades per-identity precision for availability under cardinality pressure. Global quotas remain the hard aggregate bound; a new identity temporarily relies on that aggregate bound until an identity bucket can be allocated.

## Clock rollback and expiry

Identity bucket state persists its effective update timestamp and window. Expiry is calculated from the effective persisted timestamp rather than the untrusted current wall clock alone. Cleanup applies the same rule, preventing a backward clock adjustment from expiring a bucket before its persisted update window has elapsed.

## Agent admission

A self-signed Ed25519 relay ticket proves possession of a device key; it does not
prove enrollment. Every agent WebSocket also requires a short-lived control-plane
admission capability obtained by the native agent with a fresh device-signed proof.

The device proof is signed by the enrolled Ed25519 identity and binds the device ID,
SHA-256 SPKI fingerprint, logical slot, audience `wedecent-agent-admission`, purpose
`relay.agent.admission.acquire`, a fresh 128-bit nonce, and a 30-second lifetime.
The Edge Function loads the public key from the enrolled device row, verifies the
proof, rejects revoked or non-agent devices, and atomically consumes the proof nonce. The database locks the device row and rechecks exact public-key equality and revocation state to close the verification/issuance race.
The database applies a 64-proof-attempts-per-device and 10,000-proof-attempts-global per-60-second limits, including replay attempts and bounded cleanup
of expired replay rows.

The issued capability is signed with an agent-admission-only Ed25519 key and binds:

- Issuer: `wedecent-control-plane`
- Audience: `wedecent-relay-agent`
- Purpose: `relay.agent.connect`
- Device ID and enrolled public-key fingerprint
- Logical slot 1–32
- Lifetime: 90 seconds
- Replay: the capability JTI and device-signed relay-ticket JTI are each consumed once

The Worker compares the capability fingerprint to the public key in the relay ticket.
A terminal connection grant is not an agent-admission capability, and the terminal
connection-grant signing key is not accepted for agent admission.

The native agent requests a new capability for every slot connection and reconnect,
then sends it in `X-WeDecent-Agent-Admission`. Missing Supabase configuration, missing
signing trust, issuance failure, malformed proof, revoked enrollment, expired
capability, identity/slot/fingerprint substitution, signature failure, or replay all
fail closed. Legacy shared bearer tokens cannot open agent streams.

The Edge Function uses `WEDECENT_AGENT_ADMISSION_PKCS8_B64` and the public
`WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64` value to verify that the two signing-key
thumbprints differ; it does not need the terminal grant private key. The Worker uses
`WEDECENT_AGENT_ADMISSION_PUBLIC_KEYS_JSON`, a JSON map from independent admission
JWK-thumbprint `kid` values to base64 Ed25519 SPKI public keys. It must not reuse
`WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64`. Rotation is staged by adding the new
public key to the Worker keyring first, then switching the Edge Function signer, and
removing the old public key only after the 90-second capability lifetime and rollout
margin have elapsed. The keyring accepts at most eight keys.

The native service uses only the Supabase project URL and public publishable key. It
does not load the interactive account session and never receives a user's Supabase
access token or refresh token. The Edge Function has JWT gateway verification disabled
because device proof-of-possession is its authentication boundary.

Each DeviceRelay permits at most 32 open agent sockets and one active socket per
logical slot. A free stale socket for the same slot may be replaced; a paired/active
duplicate slot is rejected. DeviceRelay replay records use additive storage prefixes,
preserving existing connection-grant replay records and attachment/state formats.

**Revocation boundary:** device revocation is checked at issuance and again atomically
when the proof nonce is consumed. A capability issued immediately before a later
revocation remains valid until its 90-second expiry; the Worker does not yet perform a
live control-plane revocation lookup. Immediate post-issuance revocation remains an
outstanding hardening item.

**Production boundary:** this PR branch contains the native client integration, Edge
Function, database migration, and Worker verifier contract, but production secrets,
the Worker public keyring, database migration, and deployed services have not been
provisioned or validated. Source changes alone are not production activation evidence.

## Direct authorization request bounds

The direct-authorization route rejects non-POST methods and malformed target-device paths before charging a quota. Throttling still occurs before signature and grant verification.

The request body is read as a stream with a 1,024-byte ceiling and a 64-chunk ceiling. A declared Content-Length is only an early-rejection hint: actual streamed bytes are counted, and a mismatch is rejected. Missing Content-Length does not disable the bound.

## Central Durable Object performance and availability

CI runs the Worker with Wrangler's local Workers runtime and SQLite-backed Durable Objects. The integration probe checks:

- `/readyz` against the local DeviceRelay and rate-limiter objects
- invalid method/path requests do not consume the direct quota
- oversized streamed bodies are rejected
- global quota state survives a local Worker process restart
- concurrent requests using the same signed agent admission and relay ticket have exactly one winner
- a signed agent admission and relay ticket are rejected as replay after a local Worker/DeviceRelay restart
- 128 concurrent direct-authorization requests against the centralized limiter
- measured local throughput, p50, p95, and maximum request latency

The performance output is labelled `wrangler-local-sqlite-durable-objects`. It is emulator/runtime-integration evidence, not a measurement of Cloudflare's deployed Durable Object service. Actual Cloudflare staging validation is still required for throughput, tail latency, regional behavior, alarm delivery, storage recovery, and availability under platform restarts or overload.

## Release boundary

The GitHub Actions Wrangler deploy dry-run validates the Worker bundle/configuration only. It does not deploy, publish a Worker, change traffic, or prove production operation. No production deployment or traffic allocation change is part of this remediation.
