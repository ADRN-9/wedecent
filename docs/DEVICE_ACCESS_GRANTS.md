# Controlled device-access grants

## Dependency and deployment order

This change is stacked on PR #181 (security/tenant-audit-foundation-wd-cp01), which itself depends on PR #180's tenant-authorization foundation. The migration uses the organization membership model and the append-only tenant audit trigger introduced by those earlier changes. It is not independently deployable against main until that foundation is merged.

The implementation deliberately does not modify PR #180 or PR #181. Apply the migrations in repository order: tenant authorization, tenant audit foundation, then controlled device-access grants.

## Authorization contract

The only supported authenticated mutation interfaces are:

- public.create_device_access_grant(device_id, grantee_user_id, permission, expires_at)
- public.update_device_access_grant_expiry(device_id, grantee_user_id, permission, expires_at)
- public.revoke_device_access_grant(device_id, grantee_user_id, permission)

Every RPC requires a non-null auth.uid(), an authenticated JWT role, and an explicit is_anonymous=false claim; missing or anonymous claims fail closed. No RPC accepts an actor ID or granted_by; inserts derive granted_by from the verified JWT subject. The device-access Edge Function verifies the bearer token with Supabase Auth and forwards that same bearer token to the authenticated RPC. Its service credential is used only for auth.getUser, not for grant-table writes.

The only supported permissions are `terminal.connect` and `mesh.forward`. They are independent, exact grants: neither implies the other, and each RPC receives the permission being created, updated, or revoked. Device owners retain their existing direct device-management authority. Otherwise, the caller must have a current owner or admin membership in the device's organization. Ordinary members and users from other tenants are denied.

Revoked devices cannot receive new grants or have grant expirations changed. Existing `device_access` rows are not silently deleted when a device is revoked. A current organization owner/admin (or the device owner) may still inspect and explicitly revoke an existing grant on a revoked device; ordinary members cannot inspect other users' stale grants. This cleanup operation only removes authority and is recorded by the existing audit trigger. This policy keeps stale authorization records manageable without making a revoked device usable again.

A NULL expires_at continues to mean a permanent grant. Non-NULL expirations must be finite PostgreSQL timestamps and in the future when evaluated after the relevant locks are acquired. Both positive and negative timestamp infinities are rejected by the RPC boundary. Expired grants cannot be revived through the expiry-update RPC, but an expired row may still be revoked.

## Locking and audit

All three RPCs use the same lock order:

1. Organization row (FOR SHARE), when the device belongs to an organization.
2. Device row (FOR UPDATE), followed by revalidation of its organization association and revocation state.
3. Caller membership row (FOR SHARE), including non-manager rows, followed by revalidation of its captured role.
4. Existing device-access row (FOR UPDATE) for update/revoke; create checks for an existing key after the device lock has serialized same-device grant creation.

This makes membership downgrade/removal wait for an already-authorized grant transaction, or causes a grant transaction waiting behind a downgrade/removal to observe the new role or missing membership and fail closed. A device reassignment detected between the initial association read and the device lock raises SQLSTATE 40001.

The existing device_access_audit_event trigger records grant, expiry-update, and revoke events. The trigger derives authenticated actors from auth.uid(); a caller-controlled wedecent.audit_actor_user_id setting cannot override a non-null authenticated subject.

## Privilege boundary and backend caller audit

The account-authorization migration originally granted authenticated users table-level SELECT/DELETE, column-level INSERT, and column-level UPDATE on public.device_access, with matching insert/update/delete RLS policies. The new migration revokes all table and column-level writes, retains RLS-filtered SELECT, and drops those obsolete write policies.

The original migration also granted service_role all table privileges. The repository's current Supabase Edge Function entrypoints were reviewed:
- connection-grant calls the dedicated issue_connection_grant RPC.
- device-enrollment uses the enrollment challenge interface and complete_device_enrollment RPC.
- route-authorization calls issue_route_authorization.
- None of those backend callers directly inserts, updates, or deletes public.device_access.

Accordingly, service_role is now read-only for this table. It cannot execute the new authenticated RPCs. This is intentionally narrower than its other control-plane table permissions. Existing trusted enrollment and connection-grant operations are unchanged.

## Retry contract

The device-access Edge Function retries only explicit PostgreSQL transaction-abort SQLSTATEs 40001 (serialization failure) and 40P01 (deadlock), with at most three attempts and 20/40 ms backoff. It does not retry authorization errors, validation errors, duplicate grants, missing rows, or thrown/network errors whose commit outcome may be ambiguous. Exhausted transaction-abort errors return HTTP 503. Direct authenticated RPC clients should apply the same bounded policy if they need automatic transient retry.

## Verification

The database pgTAP suite covers:
- RLS, including manager-only visibility of revoked-device grant records, table/column privileges, service-role read-only access, RPC ownership, SECURITY DEFINER, empty search_path, and execute ACLs;
- owner, administrator, ordinary member, device-owner (including organization-managed devices), anonymous/missing-claim rejection, and cross-tenant authorization for both permission types;
- independent `terminal.connect`/`mesh.forward` creation, update, revocation, and permission separation; existing permanent routing-grant management; positive-infinity rejection for create/update; revoked-device cleanup policy; missing authentication, actor spoofing, malformed IDs, revoked-device create/update denial, expired requests, duplicates, and missing grant rows;
- audit actor attribution, permanent-grant semantics, rollback of both grant and audit rows, and expired-row revocation.

A disposable-database two-session harness verifies grant-first versus membership downgrade, downgrade-first versus grant creation, membership-removal-first versus grant creation, and both orderings between grant creation and trusted device revocation. It also verifies that an administrator can clean up a grant after device revocation. Deno tests exercise the bounded retry helper. These tests run in the repository's GitHub Actions CI; they are not claimed as locally executed by this worker.

## Scope exclusions and limitations

This batch does not redesign organization deletion or connection/route capability revocation. It does not revoke any existing connection grant or alter the separate enrollment/connection/route RPCs. The change remains dependent on the unmerged PR #180/#181 foundation until the branch chain is merged.
