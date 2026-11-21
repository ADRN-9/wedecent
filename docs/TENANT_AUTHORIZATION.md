# WD-CP01 — Tenant authorization findings

## Scope and starting point

This review is based on repository commit `efbb37c9c81922351156b2a6d72e9f0ad1c446cb` (PR #179 head), stacked on the existing open PRs #176–#178. The control-plane SQL and Edge Function files under `supabase/` are unchanged between `main` and that starting commit.

The review covers organization RLS, membership roles, device ownership, device enrollment, terminal connection grants, route authorization grants, and the presence or absence of tenant-scoped session/audit resources.

## Findings and changes

### Fixed: organization creator was treated as a permanent authority

The original organization SELECT, UPDATE, and DELETE policies accepted `created_by = auth.uid()` as an alternative to current membership/owner status. A creator who was later removed from `organization_memberships` could still read and update the organization and delete it, cascading away its membership rows and detaching devices from the organization.

The migration `20261120100000_harden_tenant_authorization.sql` removes that fallback:

- SELECT requires current organization membership.
- UPDATE requires current owner/admin membership.
- DELETE requires current owner membership.

`created_by` remains provenance only. Organization creation still atomically creates the first owner membership through the existing SECURITY DEFINER trigger.

### Fixed: enrollment RPC did not enforce tenant authorization itself

Before WD-CP01, the Edge Function checked that the authenticated user was an owner/admin of the requested organization, but the service-role-only `complete_device_enrollment` RPC did not repeat that authorization. It also did not check the current organization before changing an existing device's `organization_id`.

The replacement RPC:

- rejects missing or malformed enrollment identity parameters, including a null public key;
- rejects a missing authenticated-user context;
- requires current owner/admin membership in the destination organization;
- requires current owner/admin membership in the existing organization before moving or unassigning an organization device;
- locks all relevant membership rows in deterministic organization-ID order with `FOR SHARE`, so a concurrent role change or membership deletion cannot race past the authorization check;
- preserves the existing one-time challenge lock/consumption, owner check, revoked-device check, public-key match, device-kind match, and service-role-only execute grant.

The Edge Function continues to derive the user ID from a server-verified Supabase Auth token. The RPC is not granted to `authenticated` or `anon`.

## Explicit ownership semantics retained

The existing account-authorization contract states that a user who owns a device may connect to it, independently of organization role. The `owner_user_id` access path in device visibility and connection-grant authorization is therefore unchanged.

Consequently, removing a user from an organization does not by itself revoke that user's direct device-owner authority for devices whose `owner_user_id` still names them. Organization offboarding that must revoke this direct path needs an explicit ownership-transfer/revocation workflow; WD-CP01 does not silently redefine device ownership.

## Existing control-plane resources and gaps

The migrations currently define:

- `organizations`
- `organization_memberships`
- `devices`
- `device_access`
- `device_enrollment_challenges`
- `connection_grants`
- `route_authorization_grants`

The enrollment challenge, connection-grant issuance, and route-grant issuance paths are server-controlled. Authenticated clients cannot directly write device identity, enrollment challenge, connection-grant, or route-grant records. The connection and route grant RPCs remain service-role-only.

There is no tenant-scoped `sessions`, `session_events`, `audit_events`, or organization audit-search/retention table/API in the current Supabase migrations. Existing terminal and device audit logs are endpoint-local; they are not a managed tenant audit store. The current schema therefore cannot prove or enforce cross-tenant session-history or central audit-event isolation. Those are not implemented by this bounded change and must not be represented as complete.

The repository also does not yet provide an organization-level SSO/RBAC-group/session-history control plane in these migrations. This review does not invent tables or claim those capabilities exist.

## Verification

`supabase/tests/database/tenant_authorization.test.sql` adds pgTAP cases for:

- former-creator access after membership removal;
- cross-organization organization/device/membership/device-access/grant visibility;
- unauthorized organization metadata and membership administration;
- cross-tenant terminal grant denial;
- organization-device unassignment and enrollment denial without current owner/admin membership;
- successful enrollment by a current organization owner;
- preservation of the documented direct device-owner visibility path.

The test suite must run through the repository's disposable Supabase database CI job on the exact PR head before the remediation is considered verified. No hosted/production Supabase database is modified by this change.
