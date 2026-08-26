# Client account enrollment

`wd account enroll` binds the local `wd` Ed25519 identity to the currently signed-in Supabase account without copying enrollment challenges or signatures through the shell.

## Flow

1. Load `account-session.json` and refresh the Supabase session when needed.
2. Load or create the local client identity in the selected client state directory.
3. POST an authenticated `action=challenge` request to `functions/v1/device-enrollment` containing the public device identity.
4. Validate that the returned challenge is bound to the same account user, device ID, public key, name, client kind, and requested organization.
5. Build the canonical `wedecent-enrollment-v1` proof locally and sign it with the device Ed25519 private key.
6. POST the proof as `action=complete` and validate that the returned device row matches the local identity and account owner.

The private identity key never leaves the endpoint. The Supabase password is not used during enrollment; enrollment uses the stored/refreshable account session.

## Usage

Personal enrollment:

```text
wd account enroll
```

Organization enrollment, when the signed-in user is an organization owner or admin:

```text
wd account enroll --organization-id <uuid>
```

`WEDECENT_ORGANIZATION_ID` may provide the organization UUID instead of the flag.

Enrollment is idempotent for the same non-revoked identity owned by the same account. The server rejects attempts to reuse the device ID with a different public key or kind, enroll a device owned by another account, or enroll a revoked device.

## Security properties

- Device IDs remain self-certifying: the control plane recomputes the device ID from the submitted public key.
- Challenges are random, short-lived, stored by digest, scoped to the account user and device, and consumed atomically by the existing enrollment RPC.
- The client validates challenge context before signing it.
- The client signs the existing canonical `wedecent-enrollment-v1` message; no new cryptographic format is introduced.
- Only the public key and signature are sent to Supabase. The Ed25519 private key stays in local device state.
- Account credentials remain in the protected account-session file: the access token is sent as an HTTPS bearer credential, and the refresh token is sent only to the configured Supabase refresh endpoint over HTTPS.
