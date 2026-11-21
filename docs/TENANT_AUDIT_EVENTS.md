# Tenant audit events

This is the first bounded database-backed tenant security-audit slice. It complements the per-device local `audit.jsonl` described in [AUDIT_EVENTS.md](AUDIT_EVENTS.md); it does not replace it.

## Data and trust boundary

`public.organization_audit_events` stores tenant-scoped security events with:

- organization ID, immutable event ID and server timestamp
- actor user ID when a verified user initiated the change, otherwise a server/service actor kind
- a fixed event type, target type and bounded target identifier
- a small JSON metadata object constrained by a database allowlist

The table intentionally has no foreign key to `organizations` or `auth.users`. Organization or user deletion therefore cannot cascade-delete audit evidence. Actor IDs remain historical identifiers even after an account is deleted.

The event metadata allowlist is limited to user/device identifiers, membership roles, device kind, permission, expiry and revocation state. It excludes arbitrary payloads, device names, public keys, connection grants/JWTs, pairing challenges or tokens, passwords, access/refresh tokens, credentials and private keys. The database also caps metadata size.

## Actor derivation

For authenticated membership and device-access mutations, trigger code derives the actor from `auth.uid()`; it never accepts an actor column from the caller.

Device enrollment is currently performed by the service-role-only `complete_device_enrollment` RPC. The existing `device-enrollment` Edge Function first validates the bearer token using `auth.getUser()`, then derives `p_user_id` from that verified user and passes it with the locked single-use challenge. The RPC checks that the challenge belongs to that user before setting the transaction-local `wedecent.audit_actor_user_id` context. The trigger honors that fallback only when `auth.role()` is `service_role`, and the RPC clears it before returning. Authenticated clients cannot set this fallback to override their JWT subject.

A trusted service operation without a verified user context is recorded with actor kind `service` and a null user ID. Database/bootstrap activity without a request actor is recorded as `system`.

## Event coverage

The current trigger set records:

- `organization.membership_added`, `organization.membership_role_changed`, and `organization.membership_removed`
- `device.enrolled`, `device.owner_changed`, `device.organization_changed`, `device.revocation_changed`, and `device.deleted`
- `device_access.granted`, `device_access.updated`, and `device_access.revoked`

Events are inserted in the same transaction as the underlying mutation. If audit insertion fails, the mutation rolls back rather than silently committing without its event. Personal devices and personal device-access changes without an organization are outside this tenant-scoped table.

## Authorization and immutability

Authenticated users receive SELECT only. Row-level security permits reads only to current organization owners and administrators through the existing `wedecent_private.can_manage_organization` policy helper. Ordinary members, former members and users from other organizations receive no rows.

No application role (including `service_role`) receives direct INSERT, UPDATE, DELETE or TRUNCATE privileges. Internal append helpers are not executable by application roles. A database trigger rejects UPDATE, DELETE and TRUNCATE even for the table owner. This is append-only against application and ordinary database roles; a PostgreSQL superuser or migration owner can still alter schema, disable triggers or otherwise bypass database controls. This is not a cryptographic tamper-evident ledger.

There is no retention/archival or tenant audit export API in this slice. Records are retained indefinitely by the schema as written; production retention, export and legal-hold policy require a separate reviewed design.

## Separate session-history API gap

This table is a security/control-plane audit trail, not a terminal session-history API. It does not provide a tenant-facing query contract for browsing sessions, duration, start/end state, device pair, transport, or session lifecycle. Existing local terminal lifecycle events remain in the local audit log; this migration does not centralize terminal session events or add a session-history endpoint. A separate bounded API should define its own RBAC, pagination, time filters, retention, correlation identifiers and privacy policy rather than expanding this foundation into an unbounded session product.

## Verification

`supabase/tests/database/tenant_audit_events.test.sql` exercises event coverage, actor derivation, secret-field exclusion, append-only behavior, and owner/admin/member/former-member/cross-organization RLS. The repository's existing `supabase-db` GitHub Actions job applies all migrations and runs `supabase test db` against a disposable local Supabase database.
