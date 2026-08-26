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
