# Native agent relay admission

## Trust boundaries

The native agent obtains one short-lived admission capability for each logical WebRelay
slot and every reconnect. Each request contains a fresh 128-bit nonce and an Ed25519
proof signed by the enrolled device identity. The proof is bound to:

- enrolled device ID and the SHA-256 fingerprint of its Ed25519 SubjectPublicKeyInfo;
- logical slot (1–32);
- audience `wedecent-agent-admission`;
- purpose `relay.agent.admission.acquire`;
- a 30-second proof lifetime.

The Edge Function loads the enrolled device public key from `public.devices`, checks
that the device is an active `agent` or `hybrid`, recomputes its ID and fingerprint,
and verifies the proof. It never accepts a user bearer token. The device row is
rechecked under a database share lock when the proof nonce is consumed, including exact equality of the enrolled public-key bytes.

Before parsing the untrusted request or looking up a device, a service-role RPC applies
a fixed global ceiling of 1,000 admission endpoint requests per rolling 60-second
window. The database proof-consumption RPC then atomically enforces one-time proof
nonces and a per-device limit of 64 proof attempts plus a 10,000-attempt aggregate
limit per rolling 60-second window, including replay attempts. Expired replay rows are
pruned in bounded batches. Issuance, successful proof consumption, rejected attempts,
rate-limit rejection, replay rejection, and device revocation are persisted as
non-secret audit events. The Edge Function issues a 90-second capability bound to
the device ID, key fingerprint, slot, audience `wedecent-relay-agent`, and purpose
`relay.agent.connect`.

The relay Worker verifies that capability with an agent-admission-only keyring and
compares its fingerprint with the public key in the device-signed relay ticket. A
terminal connection grant remains a separate authorization domain and is not accepted
as an agent-admission capability. The Worker also consumes both the admission JTI and
the relay-ticket JTI through its existing replay controls. Legacy shared bearer tokens
cannot open agent streams. A single global Durable Object caps concurrent agent
sockets at 1,024 across the Worker deployment. Established agent sessions expire after
15 minutes without terminal traffic or after 12 hours absolute lifetime, whichever
comes first.

## Runtime configuration

The native service receives only public application configuration. The Go client uses
a standard certificate-verifying HTTP transport, enforces TLS 1.3, sets SNI and
certificate hostname verification to the exact configured Supabase host, validates
the response origin and admission path, and rejects redirects or custom transports
that could bypass the TLS policy (loopback HTTP is permitted only for local tests):

- `supabase_url` / `--supabase-url`: the Supabase project origin;
- `supabase_publishable_key` / `--supabase-publishable-key`: the public publishable key.

The agent sends the publishable key in the `apikey` header. It does not load the
interactive account session and must never receive a user's Supabase access token or
refresh token. Do not place user credentials in service arguments, environment
variables, config files, or machine-wide state.

The Supabase function must have JWT gateway verification disabled because its
authentication is the device-signed proof, not a user JWT:

```toml
[functions.agent-admission]
verify_jwt = false

[functions.device-revocation]
verify_jwt = false
```

The device-revocation function validates the caller's Supabase user session and
requires device ownership or organization owner/admin authority. It records
`devices.revoked_at` first (which triggers a durable revocation audit event), then
dispatches an authenticated revocation event to the relay Worker. The Worker resolves
all active target relays associated with the revoked device, including sessions where
the device is the client, and closes the established WebSockets. It also records a
five-minute global revocation tombstone, rejects any capability issued immediately
before revocation, and rechecks the tombstone at the Durable Object accept boundary to
close connection-setup races. The five-minute interval exceeds the current 120-second
relay-ticket and connection-grant lifetimes plus clock skew.

The function itself requires its Supabase service-role key, the independent
`WEDECENT_AGENT_ADMISSION_PKCS8_B64` secret, its matching public
`WEDECENT_AGENT_ADMISSION_PUBLIC_SPKI_B64`, and the terminal grant public key
`WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64` so it can verify the signer pair and
reject accidental key reuse. The admission private key is imported non-exportably
and is never exported as JWK. The function does not receive the terminal grant
private key. The relay Worker requires
`WEDECENT_AGENT_ADMISSION_PUBLIC_KEYS_JSON`, a JSON object mapping each agent
admission JWK thumbprint `kid` to its base64-encoded Ed25519 SPKI public key. It must
not reuse `WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64`.

## Signing-key provisioning and rotation

The agent-admission Ed25519 key pair is independent of the terminal connection-grant
key pair. Generate and store it using the production secret-management process; never
commit private material or place it in this repository.

For a rotation:

1. Add the new public SPKI and its JWK thumbprint to
   `WEDECENT_AGENT_ADMISSION_PUBLIC_KEYS_JSON` while retaining the previous key.
2. Deploy and verify the Worker keyring before changing the signer.
3. Update the Supabase `WEDECENT_AGENT_ADMISSION_PKCS8_B64` secret and
   `WEDECENT_AGENT_ADMISSION_PUBLIC_SPKI_B64` value together, then redeploy the Edge
   Function.
4. Confirm newly issued capabilities carry the new `kid` and are accepted by the
   Worker.
5. Retain the old public key for at least the maximum capability lifetime plus
   deployment propagation margin, then remove it in a separate Worker update.

The keyring accepts at most eight keys. Keep each key ID equal to the SHA-256 JWK
thumbprint calculated from the public Ed25519 JWK `{crv,kty,x}`. Never copy the
terminal connection-grant signing key into this keyring.

## Revocation configuration and operational boundary

The relay Worker requires a secret `RELAY_REVOCATION_TOKEN` containing 43–128
base64url characters (at least 256 bits when generated from 32 random bytes).
The Supabase `device-revocation` function requires the same value in
`WEDECENT_RELAY_REVOCATION_TOKEN` and an exact HTTPS origin in
`WEDECENT_RELAY_REVOCATION_URL` (for example, `https://relay.wedecent.com`).
The relay readiness probe fails when the Worker revocation authority is absent. Keep
the token only in the Cloudflare and Supabase secret stores; never put it in client
configuration or repository variables.

The revocation function persists the database revocation and a durable pending
dispatch-outbox row before contacting the relay. If the relay is unavailable or the
secret is missing, it returns HTTP 503 and leaves the outbox row pending; retrying the
same authenticated endpoint dispatches it again. There is not yet a scheduled outbox
worker, so retries are request-driven rather than automatic. The audit and dispatch
tables are service-role-only; user-facing audit search and retention policy remain
control-plane work.

Production activation requires provisioning the independent admission private key,
its matching Supabase public SPKI, the Worker admission public keyring, and the
matching relay revocation secret in both providers; applying the migrations; and
verifying the deployed Edge Function and Worker configuration. Repository changes
alone do not establish production readiness.
