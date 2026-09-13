# WeDecent Mesh Architecture

## Status

This document defines the v0.4 mesh architecture direction.

WeDecent v0.3 remains the proven compatibility and security baseline. Mesh work must be additive: the existing outbound Internet relay path continues to work while new local and routed paths are introduced.

## Goal

WeDecent should allow trusted devices to communicate across multiple transports and, when explicitly authorized, allow one WeDecent device to forward a protected session for another.

Example:

```text
Device A
   |
   | LAN / Wi-Fi
   v
Device B
   |
   | Internet
   v
Device C
   |
   | Bluetooth
   v
Device D
```

A and D do not need to share a transport. Intermediate nodes forward protected WeDecent session traffic without gaining access to endpoint plaintext.

## Initial non-goals

The first mesh implementation is not:

- a general-purpose IP router
- a public SOCKS/HTTP proxy
- an unrestricted Internet exit network
- a VPN for arbitrary applications
- an anonymous routing network
- a replacement for the existing v0.3 path

Initial routing carries WeDecent protocol sessions only.

## Security invariants

The following properties remain mandatory:

1. Device private keys remain local.
2. Raw terminal/session plaintext is not placed in the control plane.
3. Endpoint possession and account/user authorization remain independent checks.
4. Routers forward protected session traffic and do not gain endpoint plaintext.
5. Router participation is explicit opt-in.
6. Routing is never implicitly public.
7. Forwarding requires authorization and expiry.
8. Replay protection remains mandatory for single-use authorization artifacts.
9. Secrets and bearer credentials must not appear in URLs or logs.
10. Normal uninstall preserves device identity unless destructive purge is explicitly requested.
11. Windows services remain non-admin and must not run as SYSTEM/LocalSystem.

## Node identity and capabilities

A WeDecent node has one cryptographic identity independent of transport addresses.

A node may advertise independent capabilities:

- `client`: can initiate sessions
- `endpoint`: can accept sessions
- `router`: can forward authorized WeDecent sessions

A device may expose multiple transports such as LAN/Ethernet, Wi-Fi, Internet, Bluetooth, and future Wi-Fi Direct or other local transports.

Addresses and transport locators belong to links, not to device identity.

## Core abstractions

### Peer

A discovered or known WeDecent node plus the information needed to attempt an authenticated link.

### Transport

A mechanism for discovering or dialing neighboring WeDecent nodes.

Conceptually:

```go
type Transport interface {
    Name() string
    Discover(ctx context.Context) (<-chan Peer, error)
    Dial(ctx context.Context, peer Peer) (Link, error)
}
```

This is architectural guidance, not yet a frozen API.

### Link

An authenticated neighbor-to-neighbor communication path over one transport.

A link may track peer identity, transport, health, latency estimate, bandwidth estimate, metered/unmetered state, and availability.

### RouteHop

One forwarding step in a route.

### Route

An ordered path from source to destination.

```text
direct:
A -> D

one-hop:
A -> B -> D

future multi-hop:
A -> B -> C -> D
```

A route should include source, destination, ordered hops, route ID, expiry, authorization context, loop-prevention data, and cost.

### RouterPolicy

Controls whether and how a node forwards traffic.

Future policy fields may include enabled, organization-only, trusted-devices-only, public-routing, max concurrent sessions, max bandwidth, allow on battery, allow on metered network, and LAN-only.

Defaults should favor safety and user control.

### RoutePlanner

Chooses an authorized path to a destination.

Initial preference should approximately be:

1. direct local LAN/Wi-Fi
2. direct existing Internet path
3. authorized one-hop trusted router
4. existing WeDecent relay path
5. Bluetooth where appropriate
6. multi-hop mesh routes

Later route cost may include latency, bandwidth, reliability, hop count, battery impact, metering, congestion, and administrator preference.

## Discovery vs routing

Discovery answers: Which nodes or links can I directly observe?

Routing answers: How can I reach destination node X?

The systems are related but must remain separate.

## Router behavior

A router authenticates neighboring links, validates forwarding authorization and route constraints, forwards protected session frames, enforces resource limits, logs operational metadata without terminal plaintext, and tears down forwarding when authorization expires or a route fails.

A router must not decrypt endpoint session content.

## Authorization model

Initial forwarding should be restricted to trusted relationships such as same account, same authorized organization, or explicit trusted-device relationships.

A node with router capability is not automatically a public relay.

Public community routing is a later feature and must require explicit opt-in.

## Failure model

Mesh routing must fail closed. If a preferred path fails, discard stale route/link state, try another authorized path, and fall back to the proven v0.3 Internet relay path when available.

A routing failure must never weaken authentication or authorization requirements.

## Implementation sequence

### Stage 1 — mesh primitives

Introduce Peer, Transport, Link, RouteHop, Route, RouterPolicy, and RoutePlanner. No production connection path changes.

### Stage 2 — direct LAN

Trusted devices on the same LAN discover each other and establish a direct protected connection. Extend the existing discovery subsystem rather than duplicate it.

### Stage 3 — trusted one-hop routing

Support `A -> B -> C`, where B is an explicitly authorized router. Solve authorization, expiry, forwarding limits, loop prevention, failure propagation, safe logging, and bandwidth accounting.

### Stage 4 — automatic path selection

Choose among direct LAN, direct Internet, trusted one-hop routing, and the existing relay fallback.

### Stage 5 — multi-hop

Only after one-hop routing is proven, add bounded-hop multi-hop routing with loop prevention.

### Stage 6 — Bluetooth

Bluetooth must fit behind the same Transport abstraction, but is intentionally not implementation #1 because OS lifecycle/background behavior differs substantially across platforms.

## GUI/Core boundary

The future GUI must not reimplement identity, authorization, routing, relay protocols, or cryptography.

The Go core owns identity, authentication, enrollment, trust, transport state, route selection, session cryptography, forwarding, authorization, and audit events.

Desktop/mobile interfaces should use a small versioned local API exposing high-level operations such as GetStatus, ListDevices, Connect, Disconnect, GetRouteStatus, GetTransportStatus, SetRouterPolicy, and GetRouterStats.

Private keys must never be returned through the UI API.

## UX principle

Mesh complexity should remain hidden by default. Normal users should see simple states such as:

```text
Connected - Direct
Connected - Local network
Connected - via Home Desktop
Connected - via WeDecent relay
```

Advanced users may inspect route details, transport, latency, bandwidth, and router policy.

## Public decentralized network

The intended progression is:

```text
direct devices
    ->
trusted local routing
    ->
trusted multi-hop routing
    ->
voluntary public relay nodes
```

Installation alone must never silently turn a user's machine into a public relay.
