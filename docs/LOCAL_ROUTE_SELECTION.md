# Local Core route selection policy

## Scope

`wd-core` may automatically select an explicitly configured one-hop route without accepting router, hop, transport, cost, or authorization material from the UI.

The source-side policy file is:

```text
<client-state-dir>/route-selection.json
```

The file is optional. If it is absent, disabled, or has no eligible candidate for the requested destination, Local Core preserves the existing non-routed LAN/direct/relay path selection.

This policy is **not a trust store**. It never grants a routing role and must not be used as evidence that a router, source, or destination is trusted.

## Format

Version 1 is a bounded JSON object:

```json
{
  "version": 1,
  "enabled": true,
  "source_device_id": "wd_aaaaaaaaaaaaaaaa",
  "candidates": [
    {
      "destination_device_id": "wd_bbbbbbbbbbbbbbbb",
      "router_device_id": "wd_cccccccccccccccc",
      "first_transport": "internet",
      "second_transport": "internet",
      "first_cost": 10,
      "second_cost": 20
    }
  ]
}
```

The file is capped at 1 MiB and 256 candidates. Unknown JSON fields, multiple JSON values, invalid device identifiers, unsupported transports, self-routes, repeated source/router/destination identities, and costs above the route-authorization control-plane limit are rejected.

Only `lan` and `internet` may be selected for routed hops. Bluetooth is not a routing transport in v0.4.

The policy is bound to one exact `source_device_id`. A copied policy cannot silently become active for a different local identity.

## Selection

For a `connection.connect` request, the UI still supplies only the destination device ID.

When the policy is enabled, `internal/coreconnect.PolicyRouteSource`:

1. reloads and strictly validates `route-selection.json`;
2. requires the policy source ID to equal the running Local Core identity;
3. considers only candidates whose destination exactly matches the requested destination;
4. requires each candidate router to exist in the source-owned `trusted-route-routers.json` store;
5. chooses the eligible candidate with the lowest sum of first-hop and second-hop cost; ties preserve policy-file order;
6. returns one exact internal `account.RouteAuthorizationRequest` to the existing connection backend.

The policy is re-read per request so an operator can change route selection without restarting `wd-core`. Local Core does not create this file.

## Directional trust remains independent

A candidate does not authorize any hop. The existing four directional routing trust domains remain independent:

```text
A -> B source trust:       trusted-route-routers.json
B -> A router source trust: trusted-route-sources.json
B -> C router destination:  trusted-route-destinations.json
C -> B destination router:  trusted-route-tunnel-routers.json
```

The policy source consults only A's dedicated source-to-router trust before proposing B. It never infers routing trust from `trusted-devices.json` or terminal pairing.

After a candidate is selected, the existing routed connection path still obtains a separate `mesh.forward` capability, validates its exact source/router/destination/hops/transports/cost binding, and lets B perform signature verification and durable JTI replay consumption. B and C continue to enforce their own directional trust locally.

## Failure behavior

No policy file, a disabled policy, a destination with no candidate, or candidates whose routers are not trusted for the source routing role result in **no routed decision**; Local Core continues with the existing non-routed path.

A malformed enabled policy is treated as a configuration error rather than being silently ignored. Once an eligible routed candidate is selected, the routed open remains authoritative for that connection attempt; a later route authorization, resolver, trust, or network failure is returned instead of silently changing the operator's explicit route decision into another path.

This distinction prevents an explicit local routing policy from becoming a hidden best-effort hint.

## Local file boundary

The policy file is required to be a regular non-symlink file and is tightened to mode `0600` when read, matching the existing local state hardening pattern. It contains no private keys, bearer tokens, passwords, connection grants, or route-authority signing material.

The policy file should still be treated as security-sensitive configuration because it influences which explicitly trusted router Local Core asks to use.

## Next work

The current file-backed source is deliberately small. It does not discover routers, publish route candidates through the UI API, infer B-to-C reachability, or modify router forwarding policy.

The next Local Core slices are:

1. router policy and router statistics service implementations;
2. an explicit bounded terminal-stream API before GUI terminal bytes are exposed;
3. the Windows GUI prototype over the same `v1` Local Core contract;
4. installation/autostart design only after lifecycle and upgrade behavior are specified and tested.
