# Relay connection-grant enforcement

The Cloudflare relay requires two independent credentials before admitting a client WebSocket:

1. a `wdt2` proof-of-possession relay ticket issued by the connecting client device identity; and
2. a short-lived account authorization JWT in `X-WeDecent-Connection-Grant`.

The relay verifies the JWT with the control-plane Ed25519 public key and binds it to the independently authenticated relay ticket. A terminal grant is accepted only when:

- `iss` is `wedecent-control-plane`;
- `aud` is `wedecent-relay`;
- `permission` is `terminal.connect`;
- `client_device_id` equals the `iss` device from the verified `wdt2` client ticket;
- `target_device_id` equals the device ID in the relay stream URL;
- the JWT is within its validity window and has a lifetime no longer than 120 seconds; and
- the JWT `kid` matches the configured Ed25519 verification key.

Agent relay slots do not carry connection grants. The legacy shared relay token is accepted only for agent migration and cannot authorize a client stream.

## Configure Cloudflare

Export the same Ed25519 public key corresponding to the private key used by the Supabase `connection-grant` Edge Function as DER SPKI, base64 encoded. Configure it on the relay Worker as `WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64`.

Using Wrangler from the relay Worker directory:

```powershell
npx.cmd wrangler secret put WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64
```

The value is a public key rather than a secret; using a Worker secret here avoids accidentally coupling deployment-specific key material to the repository.

## Client use

Write the `grant` field returned by the Supabase `connection-grant` Edge Function to a file with restrictive permissions, then connect with:

```bash
wd connect --connection-grant-file=/path/to/grant.jwt <device-id>
```

Do not pass the JWT directly on a command line. The grant is a short-lived bearer capability and should not be exposed in shell history or process listings.

## Pairing behavior

All `role=client` WebSocket streams require a short-lived account connection grant. Relay-based pairing now acquires a fresh grant automatically from the authenticated client account session before opening the relay stream. The grant only satisfies relay admission; the inner pairing protocol still requires the expected device fingerprint and a high-entropy single-use pairing secret before either endpoint writes trust state.
