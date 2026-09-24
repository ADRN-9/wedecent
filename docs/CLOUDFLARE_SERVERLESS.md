# WeDecent Serverless Relay on Cloudflare

This is the preferred Internet transport for the MVP.

```text
wd client  --WSS-->  Cloudflare Worker / Durable Object  <--WSS--  wd-agent
     \___________________ inner TLS 1.3 E2EE ___________________/
```

The Cloudflare relay sees encrypted TLS records and routing metadata only. The agent does not open an inbound Internet port.

## 1. Deploy the Worker

The Durable Object namespaces, Analytics Engine dataset, observability settings, and custom domain are declared in `cloudflare/relay-worker/wrangler.jsonc`.

```bash
cd cloudflare/relay-worker
npm install
npm test
npx wrangler deploy
```

Verify liveness and readiness:

```bash
curl https://relay.wedecent.com/healthz
curl https://relay.wedecent.com/readyz
```

Expected when healthy:

```json
{"service":"wedecent-relay","status":"ok","version":11}
{"service":"wedecent-relay","status":"ready","version":11}
```

`/healthz` is a shallow liveness check. `/readyz` verifies required relay bindings/configuration and both Durable Object storage paths, returning HTTP 503 with sanitized `not_ready` status when a dependency is unavailable. See [`RELAY_OBSERVABILITY.md`](RELAY_OBSERVABILITY.md) for the metrics/tracing contract and privacy boundaries.

## 2. Relay authentication v2

Normal v0.3 `wd` and `wd-agent` processes do **not** need a shared relay token. Every WebSocket upgrade carries a fresh 90-second `wdt2` proof-of-possession ticket signed by the endpoint's existing Ed25519 identity key.

The Worker verifies the ticket with Web Crypto and binds it to the requested device, relay role, and agent slot. See [`RELAY_AUTH_V2.md`](RELAY_AUTH_V2.md).

The inner pinned TLS session remains the terminal authorization boundary. A client relay ticket proves possession of a client identity key; it does not by itself authorize that identity to open a terminal on a target agent.

## 3. Relay connection admission limits

Syntactically valid `/v1/stream/<device-id>` WebSocket attempts are rate-limited before relay-ticket verification. Each attempt must pass both a source-IP bucket and a target-device bucket backed by the dedicated `RELAY_RATE_LIMIT` SQLite Durable Object namespace.

Defaults are:

- source IP: 120 connection attempts per 60-second token-bucket window;
- target device: 240 connection attempts per 60-second token-bucket window.

The device allowance is intentionally higher so a normal agent can re-establish its parked relay slots without exhausting the device bucket. Both agent and client stream attempts consume the same admission budgets. Invalid paths, invalid device IDs, invalid roles/slots, status checks, health checks, time checks, and direct-authorization requests do not consume stream-connection quota.

Optional Worker environment values can tune the limits without changing code:

- `RELAY_RATE_LIMIT_WINDOW_SECONDS` — positive integer, maximum 3600;
- `RELAY_IP_CONNECTIONS_PER_WINDOW` — positive integer, maximum 10000;
- `RELAY_DEVICE_CONNECTIONS_PER_WINDOW` — positive integer, maximum 10000.

Invalid configuration fails stream admission closed with HTTP 503. A depleted bucket returns HTTP 429 plus `Retry-After`; the response does not reveal whether the source-IP or device bucket was responsible.

The Worker trusts Cloudflare's `CF-Connecting-IP` header as the platform-provided client address. The raw address is not placed in Durable Object names or storage: the Worker hashes it with SHA-256 first. If the header is missing or malformed, requests share a single `unknown` source bucket rather than bypassing IP limiting.

Rate-limit state is durable across object eviction/restart. If the limiter namespace or its storage is unavailable, new stream admission fails closed rather than silently bypassing the limit. The limiter applies to connection attempts, not active-stream duration or bandwidth; those are separate policies.

## 4. Relay observability

Each Worker request writes a best-effort low-cardinality data point to Workers Analytics Engine and emits a sampled sanitized structured trace. Metrics contain normalized route/role/status/outcome plus count and duration only; they omit raw/hashed IPs, device IDs, URLs, credentials, tickets, grants, and terminal data.

Workers logs are sampled at 10% with invocation logs disabled and query strings redacted. Cloudflare automatic traces are sampled at 5%. Platform traces can still contain request paths, and relay request paths contain device IDs as routing metadata already visible to Cloudflare. Do not add terminal plaintext, bearer tokens, tickets, grants, JWTs, pairing material, credentials, private keys, or raw source IPs to custom logs/spans.

Non-WebSocket HTTP responses include `X-WeDecent-Trace-ID` for operator correlation. Telemetry failure never changes relay authentication/admission behavior; readiness reports missing telemetry/dependency bindings separately.

See [`RELAY_OBSERVABILITY.md`](RELAY_OBSERVABILITY.md) for schema and operational details.

## 5. Legacy/admin relay token

During migration, the Worker still accepts the existing `RELAY_ACCESS_TOKEN` from old stream binaries. The same secret also protects the operator-only `/v1/status/<device-id>` diagnostic endpoint.

Keep the secret configured in Cloudflare while older binaries exist, but do not distribute or configure it on upgraded v0.3 clients or agents.

If needed, configure it with Wrangler or the Cloudflare Dashboard as an encrypted Worker secret. Never commit or paste it into logs, screenshots, source files, or chat.

After all stream endpoints use relay-auth-v2, remove legacy stream-token acceptance and rotate the remaining admin/status credential.

## 6. Start the remote agent

No relay secret is required:

```bash
./bin/wd-agent serve \
  --listen '' \
  --web-relay https://relay.wedecent.com \
  --relay-slots 4 \
  --shell /bin/bash
```

`--listen ''` means the agent exposes no WeDecent inbound TCP listener.

## 7. Pair from the client

```bash
./bin/wd init --name system-1
./bin/wd pair \
  --web-relay https://relay.wedecent.com \
  --device-id wd_xxxxxxxxxxxxxxxx \
  --fingerprint 'SHA256:...'
```

Enter the one-time pairing secret from the agent when prompted.

## 8. Connect

The paired device stores its `wsrelay://` locator:

```bash
./bin/wd connect wd_xxxxxxxxxxxxxxxx
```

No shared relay token is required for the stream.

## Security notes

- `wdt2` tickets are short-lived and signed with endpoint Ed25519 identity keys.
- Agent tickets are self-bound to the agent device ID and a specific parked slot.
- Client tickets are target-bound, but account-level permission is still enforced by the target agent's paired-client trust store, not by Cloudflare.
- The Worker cannot decrypt terminal contents.
- Stream admission has source-IP and target-device attempt rate limits; identity/account-specific quotas remain future control-plane work.
- Relay custom metrics and logs deliberately omit raw IPs, device IDs, credentials, tickets/grants, and terminal contents; platform traces can contain routing paths.
- Rate limiting and observability do not replace relay authentication, connection grants, terminal trust, or the inner pinned TLS session.
- Rotate any legacy `RELAY_ACCESS_TOKEN` that has ever been distributed to endpoints once migration is complete.

## Relay status diagnostic

The status endpoint remains operator-only during this phase:

```bash
curl -sS \
  -H "Authorization: Bearer $WEDECENT_RELAY_TOKEN" \
  https://relay.wedecent.com/v1/status/wd_exampledeviceid
```

It returns counts for total/open/free agent slots and clients. The endpoint never returns terminal data or secrets.
