# Local router service boundary

## Current authority

The live one-hop forwarding router is currently owned by `wd-agent`, not `wd-core`.

`wd-agent` creates the production `meshruntime.Runtime` only when an operator explicitly configures a routing listener. Its router policy is the `mesh.RouterPolicy` attached to the same `mesh.Forwarder` that validates, authorizes, capacity-limits, and forwards routed sessions.

A route-control listener is explicit router opt-in. A route-tunnel-only listener makes the node a routed destination but does not make it a forwarding router.

`wd-core` is a separate per-user process. It opens client state, owns the Local Core API, and currently has no reference or authenticated control channel to the `wd-agent` routing runtime. The client and agent state directories are also distinct roles.

Therefore Local Core must not satisfy the v1 router API by inventing a second in-memory or file-backed policy/statistics registry. Such a registry could disagree with the process that actually enforces forwarding.

## Runtime observability

The authoritative `mesh.Forwarder` exposes a defensive process-local snapshot containing:

- the exact construction-time `mesh.RouterPolicy` used by forwarding checks;
- current active forwarding-capacity reservations;
- cumulative sessions that reached opaque forwarding after authorization and destination-link verification;
- cumulative opaque bytes observed in both forwarding directions.

The byte and session counters are process-local and are not persisted. Byte accounting saturates instead of wrapping on overflow. Failed validation, authorization, capacity, or destination setup does not increment forwarded-session totals. A route-open acceptance write must also succeed before `ServeRouteOpen` counts the session as forwarded.

`meshruntime.Runtime.RouterState` returns the snapshot from its actual `Router` instance. It contains no trust-store entries, route capabilities, replay state, bearer credentials, private keys, or session payload.

## Why Local Core is not wired yet

The existing v1 contract includes router policy and router statistics operations, including policy mutation. Correctly composing those methods requires an authority boundary between the per-user Local Core and the process that owns routing listeners.

A policy setter cannot safely mutate only a `mesh.RouterPolicy` value. Enabling or disabling participation must remain consistent with routing-listener lifecycle, process identity, state ownership, and the explicit opt-in rule. In particular, setting `Enabled=true` in `wd-core` while no `wd-agent` route-control listener exists would create a false UI state rather than router participation.

The next router-service slice should therefore choose and test one explicit ownership model before exposing the v1 methods from default `wd-core` composition:

1. add an authenticated, least-privilege local control channel to the routing owner; or
2. deliberately consolidate routing-listener ownership into the Local Core architecture.

Whichever model is chosen must preserve protected local IPC, directional routing trust, fail-closed unsupported policy behavior, listener bounds, sanitized public errors, and explicit router opt-in.

Until that boundary exists, `wd-core` should leave the router service capability uncomposed rather than report fabricated policy or statistics.
