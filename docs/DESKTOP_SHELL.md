# Phase 4 desktop shell boundary

This document fixes the trust and process boundary for the Phase 4 desktop product before a Tauri shell is introduced.

## Authority model

The desktop UI is a client only.

- `wd-agent` remains the authoritative long-lived mesh/runtime owner.
- Local Core remains the UI-facing service boundary for status, devices, connections, terminal I/O, route status, and policy operations.
- The desktop shell must not implement device trust, routing trust, router-admin trust, transport selection, TLS, pairing, relay authorization, key storage, or terminal authorization itself.
- The shell must not duplicate the mesh runtime or create an independent routing/connection manager.
- The existing Ed25519 identity, TLS 1.3 pinning, pairing, authorization, and fail-closed transport semantics remain unchanged.

The existing `internal/coreapi/v1` contract is the starting application boundary. New desktop functionality should extend that contract deliberately rather than reaching around it into transport/runtime packages.

## Process shape

The intended Phase 4 shape is:

```text
Tauri window + web frontend
        |
        | local application bridge only
        v
Local Core v1 client boundary
        |
        v
wd-agent / authoritative runtime
        |
        +-- direct LAN/TCP
        +-- RFCOMM
        +-- USB serial
        +-- relay/routed paths
```

The Tauri process may own presentation concerns such as windows, tabs, keyboard input, terminal rendering, menus, notifications, profiles, and local UI preferences. It must not become a second source of truth for connection or trust state.

## Security requirements

1. No network listener is introduced for desktop IPC merely to simplify frontend integration.
2. Existing protected local IPC remains the trust boundary. If a bridge process is introduced, it must remain local-only and narrow.
3. The frontend must never receive private keys, refresh/access tokens, pairing secrets after use, or raw trust-store contents.
4. Device discovery metadata is display/routing data only. Bluetooth names, MAC addresses, USB descriptors, serial paths, IP addresses, proximity, or OS pairing state must never become authentication evidence.
5. A desktop device picker must preserve explicit ambiguity handling. Multiple viable unpaired candidates require explicit user selection; identity conflicts fail closed.
6. Explicit transport choices must never silently fall back to another transport.
7. Renderer compromise must not automatically imply access to identity private keys or long-lived account tokens.
8. Router administration stays on its separate local administrative boundary; it must not be folded into ordinary terminal trust.

## First implementation slices

Phase 4 should be delivered as small, independently reviewable changes:

1. Tauri shell scaffold with no security/runtime logic.
2. Narrow local application bridge to the existing Local Core v1 surface.
3. xterm.js renderer wired only to terminal read/write/resize operations.
4. Device list using Core-owned device/transport/route state.
5. Multiple tabs with Core-owned connection IDs; no duplicated session authority.
6. Profiles containing presentation/connection preferences only; never private key or token material.
7. File transfer and port forwarding only after protocol/API contracts define authorization, limits, cancellation, and auditing.

## Definition of done for the Tauri shell roadmap item

Do not mark `Tauri desktop shell` complete merely because a window opens. It is complete only when:

- the shell builds in canonical CI for the supported desktop platforms selected for the milestone;
- startup connects through the approved local application/Core boundary;
- the shell can render Core status without implementing trust/network logic itself;
- Core unavailable/restart behavior is explicit and fail-closed;
- no TCP fallback or externally reachable desktop control endpoint exists;
- the architectural boundary above is covered by tests or build-time checks where practical.

## Relationship to the existing `wd-ui`

`cmd/wd-ui` already contains a Windows-native prototype and a platform-neutral `internal/guiapp` controller over Local Core. That code is useful behavior/reference, but Phase 4 must not run the Windows prototype and Tauri shell as competing authorities.

Migration should preserve the tested controller/Core semantics while moving presentation into the Tauri frontend. During migration, only one UI process should own a given interactive desktop session.

## Discovery UX

Richer Bluetooth and USB enumeration may be added to the desktop picker, but enumeration remains a locator convenience only. The picker must not claim that OS discovery output proves the expected WeDecent fingerprint. Pairing continues to require independently verified identity under the existing trust contract.
