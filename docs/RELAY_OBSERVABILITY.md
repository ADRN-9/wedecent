# Relay observability

The Cloudflare relay has three production observability layers: liveness/readiness health checks, aggregate request metrics, and sampled request tracing.

## Health endpoints

`GET /healthz` is a shallow liveness check. It does not depend on Durable Object storage or Analytics Engine and returns HTTP 200 while the Worker can execute.

`GET /readyz` is a dependency/configuration readiness check. It returns HTTP 200 only when:

- the `RELAY_METRICS` Analytics Engine binding is present;
- relay rate-limit configuration parses successfully;
- the `DEVICE_RELAY` Durable Object can execute and read its SQLite storage;
- the `RELAY_RATE_LIMIT` Durable Object can execute and read its SQLite storage.

A failed readiness check returns HTTP 503 with a sanitized `not_ready` status. Neither endpoint returns provider errors, binding names, storage details, device identifiers, or secrets. Both responses use `Cache-Control: no-store`.

## Aggregate metrics

The `RELAY_METRICS` binding writes to the `wedecent_relay_metrics` Workers Analytics Engine dataset. One data point is emitted for each Worker request.

The schema is deliberately low-cardinality:

- `index1`: normalized route (`health`, `ready`, `time`, `direct_authorize`, `status`, `stream`, or `not_found`);
- `blob1`: normalized route;
- `blob2`: normalized relay role (`agent`, `client`, or `none`);
- `blob3`: HTTP status code;
- `blob4`: bounded outcome (`success`, `upgraded`, `rejected`, `rate_limited`, `server_error`, or `exception`);
- `double1`: request count (`1`);
- `double2`: rounded request duration in milliseconds, clamped to 24 hours.

Metric writes are best-effort and never change relay authorization or availability. A metrics ingestion failure does not fail the user request.

The dataset intentionally does **not** contain raw or hashed source IPs, target/client device IDs, relay slot numbers, URLs, query strings, bearer tokens, relay tickets, connection grants, JWTs, fingerprints, terminal bytes, or request/response bodies.

Operators query Analytics Engine through Cloudflare's Analytics Engine SQL API/dashboard using account-scoped credentials. Those credentials do not belong in the Worker.

## Request tracing

Each Worker request gets an independent random trace ID. Sampled structured logs contain only:

- event name `relay_request`;
- generated trace ID;
- normalized route and role;
- status/outcome;
- bounded duration.

Non-WebSocket HTTP responses also return the trace ID in `X-WeDecent-Trace-ID` so an operator can correlate a reported failure with sampled logs. WebSocket upgrade responses are not reconstructed merely to add this header; their trace ID remains available in relay logs/traces.

Wrangler enables persisted Workers logs at a 10% head sample and automatic Workers traces at a 5% head sample. Invocation logs are disabled and log query strings are redacted. Automatic platform traces can still contain the request path; stream/status/direct-authorize paths contain a device ID because that ID is routing metadata already visible to the Cloudflare relay. They must never contain terminal plaintext or authorization secrets. Do not add raw IP addresses, tickets, grants, JWTs, pairing material, credentials, private keys, or terminal data to custom logs/spans.

Inbound application-controlled trace context is not accepted or propagated by WeDecent code. The relay uses its own correlation ID and Cloudflare's configured tracing.

## Operational checks

After deployment:

```bash
curl -fsS https://relay.wedecent.com/healthz
curl -fsS https://relay.wedecent.com/readyz
```

A healthy deployment reports `ok` for liveness and `ready` for readiness. Alerting should normally use `/readyz`; `/healthz` is intended to distinguish a dead Worker from an unavailable dependency/configuration.
