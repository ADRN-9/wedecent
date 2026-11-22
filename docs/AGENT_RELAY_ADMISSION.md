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
rechecked under a database share lock when the proof nonce is consumed.

The database RPC atomically enforces one-time proof nonces and a per-device issuance
limit of 64 proof attempts per rolling 60-second window, including replay attempts. Expired replay rows are
pruned in bounded batches. The Edge Function issues a 90-second capability bound to
the device ID, key fingerprint, slot, audience `wedecent-relay-agent`, and purpose
`relay.agent.connect`.

The relay Worker verifies that capability with an agent-admission-only keyring and
compares its fingerprint with the public key in the device-signed relay ticket. A
terminal connection grant remains a separate authorization domain and is not accepted
as an agent-admission capability. The Worker also consumes both the admission JTI and
the relay-ticket JTI through its existing replay controls. Legacy shared bearer tokens
cannot open agent streams.

## Runtime configuration

The native service receives only public application configuration:

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
```

The function itself requires its Supabase service-role key, the independent
`WEDECENT_AGENT_ADMISSION_PKCS8_B64` secret, and the terminal grant public key
`WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64` so it can reject accidental key reuse.
It does not receive the terminal grant private key. The relay Worker requires
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
3. Update the Supabase `WEDECENT_AGENT_ADMISSION_PKCS8_B64` secret to the new PKCS#8
   private key and redeploy the Edge Function.
4. Confirm newly issued capabilities carry the new `kid` and are accepted by the
   Worker.
5. Retain the old public key for at least the maximum capability lifetime plus
   deployment propagation margin, then remove it in a separate Worker update.

The keyring accepts at most eight keys. Keep each key ID equal to the SHA-256 JWK
thumbprint calculated from the public Ed25519 JWK `{crv,kty,x}`. Never copy the
terminal connection-grant signing key into this keyring.

## Remaining operational/security boundary

Device revocation is checked at issuance and again atomically when a proof nonce is
consumed. A capability already issued immediately before a later revocation remains
cryptographically valid until its 90-second expiry; the Worker does not yet perform a
live control-plane revocation lookup. Immediate post-issuance revocation therefore
remains a follow-up hardening item.

Production activation requires provisioning the independent signing secret and Worker
public keyring, applying the migration, and verifying the deployed Edge Function and
Worker configuration. Repository changes alone do not establish production readiness.
