# Local router service boundary

## Authority

The live one-hop forwarding router is owned by `wd-agent`, not `wd-core`.

`wd-agent` creates the production `meshruntime.Runtime` only when an operator explicitly configures a routing listener. Its router policy is the `mesh.RouterPolicy` attached to the same `mesh.Forwarder` that validates, authorizes, capacity-limits, and forwards routed sessions.

A route-control listener is explicit router opt-in. A route-tunnel-only listener makes the node a routed destination but does not make it a forwarding router. The local router-admin endpoint is therefore created only when a route-control listener is configured; it is not created for a route-tunnel-only destination.

`wd-core` remains a separate per-user process that owns the UI-facing Local Core API and client connection lifecycle. Router policy and statistics are not mirrored into a second in-memory or file-backed registry in that process because such a registry could disagree with the router that actually enforces forwarding.

## Chosen control model

Local Core acts as a client of the authoritative `wd-agent` router runtime through a distinct machine-local administrative channel.

The control surface is intentionally narrow:

- get the current router policy;
- atomically set policy for future routed sessions;
- get aggregate process-local forwarding statistics.

It does not expose routing trust stores, terminal trust, route capabilities, capability replay state, endpoint payloads, credentials, private keys, or general agent administration.

The channel uses the existing bounded v1 framing but accepts only the three router methods. Each operation uses one authenticated stream and one response. Reads, writes, and the TLS handshake are independently bounded. A client that opens a connection and then stops sending cannot hold an agent handler indefinitely.

## Machine-local transports

A route-control-enabled `wd-agent` binds a dedicated router-admin endpoint only on platforms with an implemented machine-local transport. No router-admin TCP listener is opened.

### Windows

Windows uses the fixed named pipe:

```text
\\.\pipe\WeDecent.RouterAdmin.v1
```

`go-winio` supplies the named-pipe transport and rejects remote named-pipe clients. The pipe ACL grants local access to SYSTEM, Administrators, and authenticated users so an interactive `wd-core` can reach an agent running under a service identity.

### Linux

Linux uses the fixed abstract Unix-domain socket:

```text
@wedecent-router-admin-v1
```

The leading `@` is Go's representation of the Linux abstract Unix-socket namespace. No filesystem socket is created, so the transport does not depend on a shared writable directory between an agent service identity and an interactive Local Core user and is not exposed to filesystem symlink or stale-socket replacement races.

The abstract namespace is machine-local but does not provide filesystem ACL authorization. Any local process can attempt to open the byte stream, and another local process could occupy the fixed socket name before `wd-agent` starts, causing startup to fail rather than falling back to another transport. This is a local denial-of-service possibility, not an authorization path: every administrative request must still complete the dedicated mutual-TLS authentication described below.

On both Windows and Linux, opening the local endpoint is not authorization. The agent limits concurrent router-admin connections separately from routed-session limits, and mTLS plus dedicated controller trust gates every request before router methods are parsed.

Other platforms currently fail closed with `routercontrol.ErrLocalEndpointUnsupported`; there is no silent TCP fallback.

## Authentication and trust separation

The router administration channel is protected independently of the platform endpoint with mutual TLS 1.3 and the dedicated ALPN `wedecent-router-admin/1`.

The Local Core controller pins both the exact agent device ID and the agent's full public-key fingerprint. The agent derives the controller device ID from the presented certificate and requires that exact identity and full fingerprint in the dedicated `trusted-router-controllers.json` trust domain.

No existing trust domain implies router-administration authority. In particular, these stores are not consulted for admin access:

- terminal/client pairing trust;
- source-to-router route trust;
- router-to-source route trust;
- router-to-destination route trust;
- destination-to-router tunnel trust.

The controller trust file is reloaded for each new administrative TLS connection. Adding or revoking a controller therefore takes effect for new admin operations without restarting the routing runtime. A missing, malformed, or unreadable trust entry fails closed.

## Controller provisioning

The Windows release bundle includes `wd-routerctl.exe` for explicit controller authorization. The same `wd-routerctl` command can be built and used on Linux. It mutates only the dedicated router-controller trust file; operators should not hand-edit that file or reuse terminal/route trust.

Trust a Local Core identity in the same agent state directory used by `wd-agent`:

```text
wd-routerctl trust --state <agent-state> --id <core-device-id> --fingerprint <core-SHA256-fingerprint> --name "Local Core"
```

On Windows, use `wd-routerctl.exe` in place of `wd-routerctl`.

List trusted controllers:

```text
wd-routerctl list --state <agent-state>
```

Revoke one:

```text
wd-routerctl revoke --state <agent-state> --id <core-device-id>
```

If the same controller device ID is intentionally rotated to a new public key, `trust` requires `--replace`; an accidental fingerprint change is rejected. The utility also refuses to assign one fingerprint to two different controller IDs. When `wd-agent` runs under a service account, provisioning may require sufficient permission to access that service's state directory.

## Local Core composition

The v1 contract exposes:

- `router.policy.get`;
- `router.policy.set`;
- `router.stats.get`.

The Local Core dispatcher implements those methods only when a `v1.RouterService` is injected. A missing router service remains `method_not_found`, preserving fail-closed behavior for installations that have not explicitly configured router administration.

On Windows and Linux, `wd-core` composes the authenticated router client only when both of these are supplied:

```text
--router-agent-id <agent-device-id>
--router-agent-fingerprint <agent-SHA256-fingerprint>
```

The equivalent environment variables are:

```text
WEDECENT_ROUTER_AGENT_ID
WEDECENT_ROUTER_AGENT_FINGERPRINT
```

Both values are required together. There is no trust-on-first-use path. The Local Core loads its existing client identity, dials the machine-local admin endpoint, authenticates itself to the agent, and pins the configured agent identity before exposing router methods through the Local Core API.

`internal/routercontrol.RuntimeService` adapts the authoritative `meshruntime.Runtime` to the v1 service. `internal/routercontrol.Client` implements the same interface over the bounded authenticated protocol, so `wd-core` is a proxy rather than a policy authority.

## Runtime policy semantics

`mesh.Forwarder.SetPolicy` validates and synchronizes policy updates on the actual forwarding runtime. Each new routed operation snapshots one policy and uses that value throughout admission, authorization, and destination setup.

Changing policy does not tear down or retroactively re-authorize tunnels that were already admitted. New sessions immediately observe the replacement policy.

The current Stage 3 implementation supports mutation of:

- `Enabled`;
- `MaxSessions`;
- `LANOnly`;
- the required trusted-device-only admission mode.

Organization routing, public routing, bandwidth enforcement, battery-aware routing, and metered-network policy remain unsupported. Requests that set those fields fail closed and leave the authoritative policy unchanged instead of reporting controls that are not actually enforced.

`Enabled` controls admission in the live forwarder. It does not create or remove the route-control listener. Listener creation remains explicit `wd-agent` configuration, preserving router opt-in. Because the router-admin endpoint exists only alongside a configured route-control listener, re-enabling policy cannot silently create a new network ingress surface.

## Runtime observability

The authoritative `mesh.Forwarder` exposes a defensive process-local snapshot containing:

- the current synchronized `mesh.RouterPolicy` used for new forwarding checks;
- current active forwarding-capacity reservations;
- cumulative sessions that reached opaque forwarding after authorization and destination-link verification;
- cumulative opaque bytes observed in both forwarding directions.

The byte and session counters are process-local and are not persisted. Byte accounting saturates instead of wrapping on overflow. Failed validation, authorization, capacity, or destination setup does not increment forwarded-session totals. A route-open acceptance write must also succeed before `ServeRouteOpen` counts the session as forwarded.

`meshruntime.Runtime.RouterState` returns the snapshot from its actual `Router` instance. It contains no trust-store entries, route capabilities, replay state, bearer credentials, private keys, or session payload.

## Operational sequence

For a Windows or Linux router managed by Local Core, the intended sequence is:

1. Configure `wd-agent` with a route-control listener. This is the router opt-in and causes the platform's machine-local router-admin endpoint to be bound.
2. Obtain the Local Core/client device ID and full public-key fingerprint through the normal identity provisioning flow.
3. Run `wd-routerctl trust` against the agent state directory to authorize that controller identity (`wd-routerctl.exe` on Windows).
4. Configure `wd-core` with the exact agent device ID and full fingerprint using the two router-agent flags or environment variables.
5. Start `wd-core`. Its v1 router methods now proxy to the live `wd-agent` forwarder.
6. Use `wd-routerctl revoke` to remove controller authority when needed; new admin connections will be denied without requiring an agent restart.

This model keeps network routing ownership, listener lifecycle, policy enforcement, and statistics in one process while still allowing the per-user Local Core to administer that runtime through a least-privilege, separately authenticated local boundary.
