# Cryptographic device enrollment

Device enrollment binds a Supabase Auth user to an existing WeDecent Ed25519 endpoint identity without allowing the browser to claim arbitrary `wd_...` IDs.

## Protocol

1. An authenticated user asks the `device-enrollment` Edge Function for a challenge and supplies the endpoint's device ID, raw Ed25519 public key, kind, display name, and optional organization.
2. The function recomputes the self-certifying device ID as `wd_` plus lower-case RFC 4648 base32 (no padding) of the first 10 bytes of `SHA-256(raw_public_key)`.
3. The function stores only `SHA-256(challenge)` in `device_enrollment_challenges` and returns the 32-byte random challenge, challenge ID, authenticated user ID, and expiry.
4. The endpoint signs the canonical `wedecent-enrollment-v1` message with its existing Ed25519 private key.
5. The function verifies the signature with Web Crypto, rechecks account/organization authorization, and invokes the service-role-only `complete_device_enrollment` RPC.
6. The RPC locks and consumes the challenge and inserts or refreshes the device row in one database transaction. Concurrent replay attempts therefore fail.

The service/secret key never leaves the Edge Function runtime. Browser-authenticated users still have no direct INSERT privilege on `devices` or enrollment challenge state.

## Canonical signed message

The UTF-8 message is exactly:

```text
wedecent-enrollment-v1
challenge_id=<uuid>
challenge=<base64url-raw-32-byte-challenge>
user_id=<supabase-auth-user-uuid>
device_id=<wd_...>
public_key=<base64url-raw-32-byte-ed25519-key>
kind=<client|agent|hybrid>
organization_id=<uuid-or-dash>
expires_unix_ms=<decimal-unix-milliseconds>
```

Every line, including the final newline, is signed. Display name is intentionally not part of the cryptographic identity; the authenticated owner may rename their device without rotating its key.

## Dashboard deployment

The repository keeps `supabase/functions/device-enrollment/index.ts` as the canonical source. When using the Supabase Dashboard editor, create a function named `device-enrollment`, paste that file, and deploy it with JWT verification enabled. Do not paste or create a service-role/secret key in browser code; hosted Edge Functions receive the project server credentials through their runtime environment.
