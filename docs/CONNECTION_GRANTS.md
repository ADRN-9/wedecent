# Short-lived connection authorization grants

A relay-auth-v2 `wdt2` ticket proves possession of an endpoint Ed25519 key. It does not prove that the signed-in account is allowed to connect that client identity to a particular target. Connection grants provide that separate account-authorization proof.

## Issuance

The `connection-grant` Supabase Edge Function authenticates a Supabase user and invokes the service-role-only `issue_connection_grant` RPC. The RPC fails closed unless:

- the client and target are different enrolled devices;
- the client is not revoked, is `client` or `hybrid`, and is owned by the authenticated user;
- the target is not revoked and is `agent` or `hybrid`;
- the user owns the target, is an owner/admin of its organization, or has a live explicit `terminal.connect` row in `device_access`.

A successful decision creates a 90-second `connection_grants` audit row. The Edge Function signs those claims with a dedicated Ed25519 control-plane key and returns a compact JWT using `alg=EdDSA`.

## JWT profile

Protected header:

```json
{"alg":"EdDSA","typ":"JWT","kid":"<RFC7638-JWK-thumbprint>"}
```

Standard claims:

- `iss = wedecent-control-plane`
- `aud = wedecent-relay`
- `sub = <Supabase user UUID>`
- `jti = <connection_grants.jti>`
- `iat` and `exp` from the server-created audit row

Private claims:

- `grant_id`
- `organization_id` (nullable)
- `client_device_id`
- `target_device_id`
- `permission = terminal.connect`

The signing private key is a dedicated Ed25519 PKCS#8 key stored only as the Supabase Edge Function secret `WEDECENT_CONNECTION_GRANT_PKCS8_B64`. Never reuse an endpoint identity key or a Supabase Auth signing key for this purpose.

## Relay binding (next milestone)

The Cloudflare relay will pin the corresponding Ed25519 public key and require both proofs on client streams:

1. a valid `wdt2` ticket whose issuer is exactly `client_device_id` and whose subject is exactly `target_device_id`;
2. a valid account grant with the same client and target, `permission=terminal.connect`, current time inside `iat..exp`, and an unused `jti` for that relay session.

The target agent's existing inner TLS/pairing trust remains an independent defense-in-depth check.
