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

`session.ManagedTerminal` is the application-session handle returned by the
connection backend. It observes natural remote close and now exposes bounded
terminal I/O to the Local Core connection manager instead of draining output.
The UI still cannot create or authorize a second terminal independently: the
stream is addressed only by an existing Local Core connection ID and therefore
reuses the exact connection grant, route authorization, path selection, TLS peer
verification, and terminal session established by `connection.connect`.

Terminal streaming is intentionally bounded:

- each `terminal.read` / `terminal.write` operation is capped at 32 KiB;
- each managed terminal retains at most 256 KiB of unread output in memory;
- output overflow terminates the terminal session instead of growing memory or
  silently dropping bytes;
- `terminal.resize` accepts only non-zero dimensions;
- input writes are deadline/context bounded and the IPC layer wipes copied raw
  input buffers on a best-effort basis after dispatch;
- after natural remote close, path/connection state disappears immediately while
  the closed terminal handle may remain briefly so final PTY output can be read;
- retained closed streams expire after 30 seconds and are additionally capped by
  the connection manager so they cannot accumulate without bound.

The connection manager observes backend lifecycle completion and removes
published path state when a remote session ends. Process shutdown cancels
in-flight backend opens, discards retained stream handles, and closes active
sessions after the bounded local IPC server drains request handlers.

Automatic routed path selection is source-owned policy. The backend accepts an
internal `RouteRequestSource`; the default `wd-core` composition uses the
source-bound policy implementation documented in `docs/LOCAL_ROUTE_SELECTION.md`.
Router/hop choices are never supplied by the UI or inferred from terminal trust.
