# Account authorization

Relay-auth-v2 answers one question: **which Ed25519 endpoint key is making this relay request?** It deliberately does not answer the account-level question: **is the signed-in user allowed to connect this client identity to this target device?**

The account-authorization layer keeps those decisions separate.

## Foundation schema

The foundation starts with `supabase/migrations/20260826160000_account_authorization_foundation.sql`. The follow-up migration `20260826180000_bootstrap_organization_owner_trigger.sql` makes first-owner creation atomic with organization creation.

It creates:

- `organizations` and `organization_memberships` with `owner`, `admin`, and `member` roles;
- `devices`, a registry of self-certifying `wd_...` endpoint identities and Ed25519 public keys;
- `device_access`, explicit per-user `terminal.connect` permission;
- `device_enrollment_challenges`, server-only one-time challenge state;
- `connection_grants`, server-only audit/revocation records for future short-lived authorization grants.

Every table in the exposed `public` schema has RLS enabled. Grants are removed first and then only the minimum authenticated operations are restored. `anon` receives no control-plane table privileges.

Security-definer helpers live in a non-exposed `wedecent_private` schema, use `search_path = ''`, and fully qualify table/function references.

## Device enrollment boundary

A browser or CLI must **not** be able to claim an arbitrary device ID by directly inserting a row into `devices`. The migration therefore provides authenticated users with `SELECT` only on that table.

Enrollment should be performed by trusted server code (for example a Supabase Edge Function) using this flow:

1. Authenticate the human user with Supabase Auth.
2. Accept the endpoint's claimed `device_id`, raw Ed25519 public key, device kind, and display name.
3. Recompute the self-certifying `wd_...` ID from the supplied public key and require it to equal the claimed ID.
4. Create a short-lived random challenge and store only its SHA-256 digest in `device_enrollment_challenges`.
5. Have the endpoint sign a domain-separated enrollment message containing the challenge, user/account context, device ID, and expiry.
6. Verify the Ed25519 signature server-side and atomically consume the challenge.
7. Insert/update the `devices` row with a service credential that is never exposed to the endpoint or browser.
8. Emit an audit event before later granting terminal access.

A challenge must be single-use and short-lived. Enrollment should fail closed on a public-key/device-ID mismatch, expired challenge, replayed challenge, revoked device, or authenticated-user mismatch.

## Authorization model

A user may connect to a target device when one of these is true:

- they own the device;
- they are an `owner` or `admin` of the device's organization;
- they have an unexpired explicit `terminal.connect` row in `device_access`.

Ordinary organization `member` status lets a user discover/read organization device metadata but does not implicitly grant terminal access.

The `connection-grant` Edge Function evaluates this policy through a service-role-only database RPC, then issues a short-lived Ed25519-signed authorization grant bound to:

- Supabase `user_id`;
- organization ID when applicable;
- enrolled client device ID;
- target device ID;
- permission (`terminal.connect`);
- issued-at and expiry;
- unique grant/JTI for audit and revocation.

The relay will require **both** the existing `wdt2` endpoint proof and this server-issued account grant for client streams. The target agent's local paired-client trust check remains defense in depth.

## RLS notes

Organization creators can insert an organization only for themselves. A locked-down `SECURITY DEFINER` `AFTER INSERT` trigger atomically creates the creator's first `owner` membership; browser-authenticated code does not bootstrap that row directly. Owner/admin membership management remains RLS-controlled, and the existing final-owner guard prevents removal or demotion of the final organization owner.

Device identity rows, enrollment challenges, and connection-grant writes remain server-only. This is intentional: RLS is not a substitute for Ed25519 proof-of-possession verification.

## Not implemented by this migration

This foundation does not yet:

- configure a Supabase project or Auth providers;
- make Cloudflare require account grants;
- synchronize device `last_seen_at`;
- replace the operator credential used by `/v1/status/...`.

Those are subsequent milestones built on this schema.
