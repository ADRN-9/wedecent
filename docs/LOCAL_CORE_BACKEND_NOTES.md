# Local Core connection backend notes

This development slice composes the Local Core `connection.connect` and
`connection.disconnect` capability with the existing authenticated networking
primitives.

The UI continues to supply only a destination device ID. Connection-grant JWTs,
relay proof-of-possession tickets, trusted peer locators, route capabilities,
and router trust remain internal to the core.

The concrete backend preserves the current connection behavior:

- paired terminal trust is required before any connection attempt;
- trusted LAN discovery may replace a relay locator only after the discovered
  fingerprint matches the paired identity and a TLS identity probe succeeds;
- direct and legacy-relay terminal authorization uses the existing in-band
  connection grant;
- serverless WebSocket relay authorization carries the same grant in the outer
  relay request and opens the existing inner terminal session without duplicating
  the grant in-band;
- routed connections use a separate internal route-request source, dedicated
  source-to-router trust, and a distinct `mesh.forward` route authorization;
- route authorization is never inferred from terminal pairing trust.

`session.ManagedTerminal` exists only as the lifecycle endpoint for the current
Local Core connection API. It drains terminal output instead of retaining or
exposing it, observes natural remote close, responds to protocol ping/close
frames, and supports explicit disconnect. A later terminal-stream API must add a
bounded UI stream instead of making this lifecycle API expose raw terminal data.

The connection manager now observes backend lifecycle completion and removes
published path state when a remote session ends. Process shutdown cancels
in-flight backend opens and closes active sessions after the bounded local IPC
server drains request handlers.

Automatic routed path selection is deliberately not invented here. The backend
accepts an internal `RouteRequestSource` policy hook, but the default `wd-core`
composition does not fabricate router/hop choices from terminal trust. A future
route-planning service can supply that hook after candidate discovery and policy
are explicitly defined and tested.
