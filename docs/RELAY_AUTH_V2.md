# Relay authentication v2

Relay authentication v2 removes the global relay bearer secret from normal `wd` and `wd-agent` WebSocket upgrades.

Each endpoint already owns an Ed25519 identity key. For every WSS upgrade it now creates a fresh, short-lived proof-of-possession ticket:

```text
wdt2.<base64url JSON claims>.<base64url Ed25519 signature>
```

The signature is computed over the exact encoded payload with the domain-separation prefix:

```text
wedecent-relay-ticket-v2\n
```

The private key never leaves the endpoint.

## Claims

A ticket contains:

- `v`: ticket version (`2`);
- `aud`: fixed audience `wedecent-relay`;
- `iss`: the signing endpoint's self-certifying `wd_...` identity;
- `sub`: target device ID;
- `role`: `agent` or `client`;
- `slot`: agent relay slot, omitted for clients;
- `iat` / `exp`: issue and expiry Unix timestamps;
- `jti`: 128-bit random ticket identifier;
- `pk`: raw Ed25519 public key encoded with unpadded base64url.

Tickets live for 90 seconds. The Worker rejects tickets with a lifetime over 120 seconds and allows at most 30 seconds of clock skew.

## Relay-relative time

Short ticket lifetimes should not require a perfectly synchronized endpoint wall clock. Before issuing each v2 ticket, upgraded endpoints fetch `GET /v1/time` from the same relay origin and derive the ticket timestamp from that HTTPS-authenticated relay clock. The response is explicitly non-cacheable.

The endpoint bounds the accepted correction to 24 hours and the time request to a 5-second round trip. Larger disagreement fails closed instead of silently widening the ticket replay window. Plain HTTP/WS remains available only for local development; production relay time must come from the HTTPS/WSS relay origin.

Worker v6 adds `/v1/time`; v2 endpoints using relay-relative time therefore require a v6-or-newer Worker.

## Worker verification

Before upgrading a stream, the Worker:

1. validates ticket encoding and claim types;
2. binds `sub`, `role`, and `slot` to the requested relay URL;
3. hashes `pk` and verifies that the resulting self-certifying ID equals `iss`;
4. requires agent tickets to be self-bound (`iss == sub`);
5. verifies the Ed25519 signature with Cloudflare Web Crypto;
6. checks issue/expiry times.

A ticket for one device, role, or agent slot therefore cannot be reused for another scope.

## Authorization boundary

Relay v2 is a **proof-of-possession and anti-secret-sharing layer**, not the final account authorization system.

For terminal access, the agent's existing end-to-end TLS and local paired-client trust store remain authoritative. A newly generated client identity can create its own relay ticket, but it still cannot open a terminal unless the target agent has paired and trusted that identity.

This means a malicious identity can still attempt availability abuse against a known device ID. Production deployments still need rate limiting and the planned account/control-plane authorization grant.

## Migration

Worker v6 accepts either:

- a `wdt2` ticket; or
- the legacy `RELAY_ACCESS_TOKEN` on stream upgrades.

Normal v0.3 clients and agents use `wdt2` tickets and do not load the legacy token. Worker v6 keeps token acceptance only so older binaries can remain online during a Worker-first migration. Upgrade the Worker before upgrading endpoints.

`/v1/status/<device-id>` remains an operator diagnostic and still requires `RELAY_ACCESS_TOKEN`. Do not distribute that token to normal endpoints once all stream clients use v2 tickets.

After all deployed endpoints have moved to v2, remove legacy stream-token acceptance and rotate the remaining admin/status token. Upgraded v0.3 endpoints intentionally require a v6-or-newer relay.

## Control-plane upgrade path

Supabase/OIDC authorization can be added without changing the inner terminal protocol. The intended next step is to require a short-lived server-issued client grant in addition to the client's identity proof. That grant can bind user, organization, device, role, expiry, and audit/session identifiers while the endpoint's Ed25519 signature continues to prove possession of the client key.
