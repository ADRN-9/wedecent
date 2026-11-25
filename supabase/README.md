# Supabase development assets

The `supabase/migrations/` directory contains the control-plane schema that will back WeDecent account authorization. The relay/terminal data path does not depend on this schema yet.

Apply migrations with the Supabase CLI against a disposable/local project first, then run `supabase test db` (pgTAP tests live in `supabase/tests/database/`), then deploy to a staging project before production. Do not place project service-role keys, database passwords, access tokens, or JWT signing material in this repository.

The account-authorization foundation intentionally gives browser-authenticated users no write privilege on `public.devices`, `public.device_enrollment_challenges`, or `public.connection_grants`. A future trusted enrollment/grant service will perform those writes only after verifying endpoint proof of possession and account authorization.

## Edge Functions

`functions/device-enrollment/index.ts` is the trusted proof-of-possession enrollment endpoint. `functions/connection-grant/index.ts` is the trusted short-lived terminal authorization issuer. Hosted deployments must keep JWT verification enabled and must never expose the project secret/service-role key or connection-grant signing private key to browsers or endpoint processes.

## Route authorization signing key

The route-authorization Edge Function requires both:

- WEDECENT_ROUTE_AUTHORIZATION_PKCS8_B64: the Ed25519 PKCS#8 DER private key encoded as standard base64 and stored only as a Supabase Edge Function secret.
- WEDECENT_ROUTE_AUTHORIZATION_PUBLIC_KEY_B64URL: the matching raw 32-byte Ed25519 public key encoded as unpadded base64url.

The function imports the private key as a non-extractable WebCrypto CryptoKey, derives kid from the separately supplied public key's RFC 7638 JWK thumbprint, and signs/verifies a fixed challenge before issuing any route authorization. A mismatch fails closed. Provision both values from the same independently generated key pair; never commit either private material or deployment secret values. The public key is a trust anchor and must be reviewed/pinned in the verifier configuration.

The private key is still supplied to the Edge runtime as PKCS#8 secret material. Non-extractable import prevents later WebCrypto export; it does not provide hardware-backed or remote signing. Production HSM/managed signing integration remains a separate hardening requirement.

Port-forward authorization is a distinct permission and signing domain. Its signing key must be provisioned separately; do not reuse the route-authorization key, device identity key, or router-administration key.
