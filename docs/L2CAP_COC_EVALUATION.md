# L2CAP CoC transport evaluation

## Decision

Do not add a first-class WeDecent L2CAP Credit-Based Connection-Oriented Channel (CoC) transport yet.

L2CAP CoC is technically usable on Linux and Apple platforms, but the current cross-platform product does not have a comparably narrow, application-level Windows path. Adding it now would create materially different platform implementations and a new packet-to-stream adaptation layer without a concrete device class that requires BLE CoC.

Keep RFCOMM as the explicit Bluetooth byte-stream transport for current Linux/Windows support. Revisit L2CAP CoC when a target device is BLE-only, when power/transport constraints make RFCOMM unsuitable, or when Windows exposes a supportable application-level CoC API for the required topology.

This evaluation does not change WeDecent identity, trust, pairing, routing, or authorization semantics.

## Required security boundary

Any future L2CAP transport must remain only a transport adapter beneath the existing session layer:

- TLS remains authoritative for endpoint identity.
- Exact WeDecent fingerprint validation remains unchanged.
- OS Bluetooth pairing, LE address, PSM, advertisement data, device name, and physical proximity must not create WeDecent trust.
- Initial WeDecent pairing still requires the expected fingerprint and single-use pairing secret.
- Terminal access still requires the existing connection-grant authorization.
- Explicit L2CAP selection must never fall back to RFCOMM, TCP, relay, or another transport after failure.
- Discovery, if later added, must remain separate from authorization.

## Linux

Linux exposes native L2CAP sockets through `AF_BLUETOOTH` / `BTPROTO_L2CAP`. BlueZ documents `SOCK_SEQPACKET` L2CAP sockets, LE address types, and credit-based flow-control channel modes.

This makes a native implementation feasible without shelling out to `bluetoothctl` or another PATH-resolved helper. A future adapter could use the same general low-level approach as the current native RFCOMM code.

However, L2CAP CoC is message/SDU-oriented rather than a normal byte-stream socket. WeDecent currently hands transports to Go TLS through `net.Conn`, whose semantics are an ordered byte stream. A Linux CoC implementation therefore needs an explicit, tested stream adapter that:

- fragments writes to the negotiated SDU/MTU limits;
- reassembles received SDUs into normal `Read` stream semantics;
- handles short application buffers without discarding the remainder of an SDU;
- preserves ordering and backpressure;
- implements deadlines and cancellation without busy loops; and
- bounds buffering so a peer cannot force unbounded memory use.

The kernel/BlueZ CoC support is therefore sufficient for feasibility, but not a reason by itself to add another production transport.

References:

- BlueZ L2CAP documentation: <https://github.com/bluez/bluez/blob/master/doc/l2cap-protocol.rst>
- BlueZ L2CAP monitor documentation: <https://github.com/bluez/bluez/blob/master/doc/btmon-l2cap.rst>

## Windows

The existing Win32 Bluetooth socket API is documented for Bluetooth Classic RFCOMM application scenarios. Windows exposes L2CAP capabilities in the Bluetooth driver stack, including Bluetooth Request Blocks used by profile drivers, while the documented application-level Bluetooth LE surface is centered on WinRT GATT APIs.

That is not an acceptable foundation for a narrow WeDecent CoC transport today:

- a kernel/profile driver is a substantially larger deployment and security boundary than the current user-mode binaries;
- GATT is not a transparent replacement for an L2CAP CoC byte-stream adapter;
- introducing a custom Windows driver solely for this transport would create signing, installation, update, privilege, and attack-surface obligations disproportionate to the current requirement.

Do not use undocumented APIs, a custom kernel driver, or a GATT tunneling protocol merely to claim L2CAP support.

References:

- Windows Bluetooth driver stack: <https://learn.microsoft.com/windows-hardware/drivers/bluetooth/bluetooth-driver-stack>
- Using the Windows Bluetooth driver stack: <https://learn.microsoft.com/windows-hardware/drivers/bluetooth/using-the-bluetooth-driver-stack>
- Windows Bluetooth developer FAQ: <https://learn.microsoft.com/windows/uwp/devices-sensors/bluetooth-dev-faq>

## macOS

Apple exposes L2CAP channel APIs. Core Bluetooth provides `openL2CAPChannel`, `CBL2CAPChannel`, and peripheral-side `publishL2CAPChannel`; IOBluetooth also exposes native L2CAP channel operations for Classic Bluetooth.

This is technically viable, but it does not fit the current pure-Go/native-socket transport shape. A production macOS adapter would require a maintained Objective-C/Swift framework bridge (or equivalent native integration), lifecycle translation into `net.Conn`, deadline/cancellation behavior, and deterministic tests on native macOS runners.

Adding that bridge before a concrete product requirement would increase platform-specific complexity while RFCOMM already covers the current Linux/Windows Bluetooth requirement.

References:

- Core Bluetooth `CBPeripheral` L2CAP APIs: <https://developer.apple.com/documentation/corebluetooth/cbperipheral>
- Core Bluetooth `CBPeripheralManager` L2CAP publication: <https://developer.apple.com/documentation/corebluetooth/cbperipheralmanager>
- IOBluetooth L2CAP channel APIs: <https://developer.apple.com/documentation/iobluetooth/iobluetoothl2capchannel>

## When to reopen implementation

Reopen this transport as an implementation item when at least one of these is true:

1. a supported target endpoint is BLE-only and cannot provide RFCOMM or an IP transport;
2. measured power, latency, or radio constraints make RFCOMM unsuitable for an identified product requirement;
3. Windows provides a supported user-mode application API for the required CoC client/server topology; or
4. the product explicitly accepts a platform-limited L2CAP feature and its maintenance/testing cost.

Before implementation, define an explicit locator that includes all connection-critical values without deriving WeDecent identity from them. PSM/address discovery may improve UX later, but discovered values remain routing hints only.

## Completion status

The roadmap evaluation item can be considered complete because platform feasibility and the implementation boundary are documented. No L2CAP transport is implemented, and no hardware-completion claim is made.
