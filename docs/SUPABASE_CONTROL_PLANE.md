# Supabase Control Plane (next phase)

Supabase should manage identities and metadata, not raw terminal bytes.

Planned responsibilities:

- Supabase Auth for users.
- Organizations and memberships.
- Device registry and device ownership.
- Role-based terminal authorization.
- Short-lived server-issued client grants.
- Session metadata and audit events.
- Row Level Security on every browser-accessible table.

The raw terminal stream remains:

```text
wd / browser client <-> Cloudflare relay <-> wd-agent
```

Relay-auth-v2 already removes the global relay secret from normal streams by using short-lived Ed25519 proof-of-possession tickets. Those tickets prove endpoint key possession and stream scope; they do **not** prove a user's account-level permission to access the target device.

The control-plane phase should add a second, server-issued grant for client connections. That grant should bind at minimum:

- authenticated user ID;
- organization ID when applicable;
- client identity ID;
- target device ID;
- allowed action/role;
- issued-at and expiry times;
- unique session/grant ID for audit and revocation.

The relay should then require both the endpoint identity proof and the server-issued authorization grant before attaching a client to an agent slot. Agent self-authentication can continue to use the device's Ed25519 proof, with device ownership/registration enforced by the control plane.

## Implemented foundation

The first account-authorization schema now lives in `supabase/migrations/20260826160000_account_authorization_foundation.sql`. It defines organizations, memberships, enrolled endpoint identities, explicit terminal access, enrollment challenge state, and short-lived connection-grant audit records. See `docs/ACCOUNT_AUTHORIZATION.md` for the security boundary and enrollment flow.

The migration deliberately does not allow browser-authenticated users to write `devices`, enrollment challenges, or connection grants. Those operations require trusted server code because database RLS cannot by itself verify possession of an endpoint Ed25519 private key.
