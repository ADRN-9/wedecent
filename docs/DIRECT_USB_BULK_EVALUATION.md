# Direct USB bulk-endpoint transport evaluation

## Decision

Do not add a first-class direct USB bulk transport to WeDecent yet.

For the current Phase 3 scope, USB CDC-ACM remains the simplest serial byte-stream option and USB NCM remains the preferred higher-throughput USB path because it reuses the existing pinned direct-TCP transport. A bespoke bulk transport would add a new host-driver/user-mode deployment surface without improving the WeDecent trust model.

This is an implementation-practicality decision, not a security exception. If direct bulk is revisited, TLS 1.3, exact WeDecent identity/fingerprint verification, pairing trust, and connection-grant authorization must remain authoritative exactly as they are for other transports.

## Device-side Linux feasibility

Linux gadget-capable systems can expose vendor-specific bulk IN/OUT endpoints from userspace with FunctionFS. FunctionFS provides endpoint files after userspace supplies descriptors and strings, while configfs can compose the FunctionFS instance into a gadget configuration.

That makes a Linux device-side prototype technically feasible without a custom kernel function driver.

USB Raw Gadget is not suitable for a production WeDecent transport. Kernel documentation describes it as a debugging-oriented interface and recommends other gadget interfaces for production use.

## Host-side constraints

A useful WeDecent transport must have a supportable host path on the platforms where the client runs.

### Linux host

Linux usbfs exposes bulk-transfer ioctls and user-mode libraries such as libusb can use them. A Linux-only host implementation is therefore feasible.

### Windows host

A vendor-specific bulk interface requires a suitable userspace-accessible driver binding such as WinUSB (or an equivalent packaged driver strategy) before ordinary application code can exchange bulk transfers. That introduces installer/driver association, device-interface discovery, signing/distribution, upgrade, and removal concerns that the current CDC-ACM and NCM paths avoid.

The repository does not currently have a production-quality WinUSB device-driver/package lifecycle for a WeDecent vendor-specific USB interface.

### macOS host

A direct vendor-specific bulk path would likewise require a separate USB user-mode integration and entitlement/deployment review instead of reusing the existing socket/serial abstractions. The repository has no such production path today.

## Protocol implications

A raw bulk endpoint pair does not itself provide message boundaries suitable for TLS. A practical adapter would have to present a reliable ordered full-duplex stream abstraction above USB transfers, including:

- partial-read/write handling;
- disconnect/re-enumeration behavior;
- bounded buffering and backpressure;
- cancellation and deadline semantics;
- deterministic endpoint/interface selection;
- exact rejection of unexpected descriptors or devices;
- no fallback to another transport after a failed explicit bulk selection.

Only after that stream abstraction exists should it be passed to the existing `session.Client` / `session.Server` TLS path. USB VID/PID, serial number, bus address, interface number, or physical possession must never become WeDecent identity or authorization.

## Comparison with NCM

The Linux NCM gadget helper already provides the higher-throughput USB use case while keeping host networking explicit and operator-managed. WeDecent then uses ordinary `tcp://` over the point-to-point link, preserving the mature direct transport, TLS pinning, authorization, timeout, and diagnostic behavior.

Direct bulk would be preferable only if at least one of these becomes true:

1. NCM cannot meet a documented latency/throughput or deployment requirement.
2. A supported cross-platform vendor-specific USB driver/user-mode access strategy is available and maintainable.
3. A hardware target cannot expose CDC-ACM or USB networking but can expose suitable bulk endpoints.

No such requirement is currently established in the repository.

## Revisit criteria

Reopen implementation work only with a concrete hardware/platform target and all of the following:

- explicit VID/PID/interface contract and ownership of those identifiers;
- documented Windows driver/WinUSB binding and signed distribution lifecycle, if Windows is in scope;
- documented macOS user-mode access strategy, if macOS is in scope;
- Linux FunctionFS or equivalent device-side lifecycle with fail-closed descriptor validation;
- a bounded `net.Conn`-like stream adapter with deadline/cancellation tests;
- native-platform CI for unsupported/fail-closed paths;
- real-hardware validation proving pairing and an authorized terminal session through the existing TLS/session stack.

Until those prerequisites exist, NCM is the preferred high-throughput USB path and direct bulk remains intentionally deferred.
