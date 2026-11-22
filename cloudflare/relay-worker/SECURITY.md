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

A self-signed Ed25519 relay ticket proves possession of a device key; it does not prove enrollment. An agent WebSocket now also requires a short-lived control-plane-signed admission JWT:

- Header: `X-WeDecent-Agent-Admission`
- Issuer: `wedecent-control-plane`
- Audience: `wedecent-relay-agent`
- Purpose: `relay.agent.connect`
- Permission: `terminal.connect` (the underlying control-plane device-access grant)
- Scope: target device ID and logical slot 1–32
- Lifetime: at most 120 seconds
- Replay: the admission JTI is consumed once; modern Ed25519 agents also consume the relay-ticket JTI in the same Durable Object transaction

The `supabase/functions/agent-admission` Edge Function issues this token by calling the existing `issue_connection_grant` authorization RPC and signing its approved result with the existing connection-grant signing key. The separate audience and purpose prevent this token from being accepted as a terminal client connection grant.

The agent runtime must obtain a fresh admission token for each slot connection and send it in the header above. The Worker fails closed if the header, public verifier key, device scope, slot, signature, expiry, or replay state is invalid. The legacy shared relay token is no longer sufficient by itself; legacy agents also need a signed admission token.

Each DeviceRelay permits at most 32 open agent sockets and one active socket per logical slot. A free stale socket for the same slot may be replaced; a paired/active duplicate slot is rejected. DeviceRelay replay records use additive storage prefixes, preserving existing connection-grant replay records and existing DeviceRelay attachment/state formats.

**Integration dependency:** this change adds the control-plane issuer and Worker contract, but does not update the native agent runtime to call the new Edge Function or attach the admission header. The Edge Function source and Worker changes are not deployed by this PR. Until the Edge Function is deployed and client integration is merged and deployed, Ed25519 and legacy agent WebSocket connections will fail closed. This is an explicit release blocker, not a production-ready claim.

## Direct authorization request bounds

The direct-authorization route rejects non-POST methods and malformed target-device paths before charging a quota. Throttling still occurs before signature and grant verification.

The request body is read as a stream with a 1,024-byte ceiling and a 64-chunk ceiling. A declared Content-Length is only an early-rejection hint: actual streamed bytes are counted, and a mismatch is rejected. Missing Content-Length does not disable the bound.

## Central Durable Object performance and availability

CI runs the Worker with Wrangler's local Workers runtime and SQLite-backed Durable Objects. The integration probe checks:

- `/readyz` against the local DeviceRelay and rate-limiter objects
- invalid method/path requests do not consume the direct quota
- oversized streamed bodies are rejected
- global quota state survives a local Worker process restart
- a signed agent admission and relay ticket are accepted once, then rejected as replay after a local Worker/DeviceRelay restart
- 128 concurrent direct-authorization requests against the centralized limiter
- measured local throughput, p50, p95, and maximum request latency

The performance output is labelled `wrangler-local-sqlite-durable-objects`. It is emulator/runtime-integration evidence, not a measurement of Cloudflare's deployed Durable Object service. Actual Cloudflare staging validation is still required for throughput, tail latency, regional behavior, alarm delivery, storage recovery, and availability under platform restarts or overload.

## Release boundary

The GitHub Actions Wrangler deploy dry-run validates the Worker bundle/configuration only. It does not deploy, publish a Worker, change traffic, or prove production operation. No production deployment or traffic allocation change is part of this remediation.
