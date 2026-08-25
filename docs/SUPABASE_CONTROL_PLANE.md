# Supabase Control Plane (next phase)

Supabase should manage identities and metadata, not raw terminal bytes.

Planned responsibilities:

- Supabase Auth for users.
- Organizations and memberships.
- Device registry and device ownership.
- Role-based terminal authorization.
- Short-lived relay authorization grants.
- Session metadata and audit events.
- Row Level Security on every browser-accessible table.

The raw terminal stream remains:

```text
wd / browser client <-> Cloudflare relay <-> wd-agent
```

For the current MVP, use `RELAY_ACCESS_TOKEN` as the relay anti-abuse gate and the existing WeDecent pairing/fingerprint model for end-to-end authentication.
