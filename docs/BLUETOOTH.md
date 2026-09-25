# Bluetooth RFCOMM transport

WeDecent supports explicit Bluetooth Classic RFCOMM transport on Linux and Windows. RFCOMM supplies only a reliable byte stream; the existing WeDecent TLS/session layers remain authoritative for device identity, pairing trust, and terminal authorization.

## Locator format

Clients use an explicit locator only:

```text
XX:XX:XX:XX:XX:XX/CHANNEL
```

`CHANNEL` must be canonical decimal `1` through `30`. The MAC address must use six colon-separated hexadecimal octets. Lowercase hexadecimal is accepted and canonicalized to uppercase.

Example:

```text
01:23:45:67:89:AB/7
```

The persisted client locator is:

```text
rfcomm://01:23:45:67:89:AB/7
```

No RFCOMM implementation performs Bluetooth discovery, SDP lookup, trust inference, automatic channel selection, or TOFU. The operator supplies the peer Bluetooth address and channel explicitly.

## Linux implementation

Linux uses native `AF_BLUETOOTH` / `BTPROTO_RFCOMM` sockets through the repository's pinned `golang.org/x/sys/unix` dependency. It does not execute `bluetoothctl`, `rfcomm`, shell commands, or PATH-resolved helpers in the production transport and does not add CGO or a dynamic BlueZ-library dependency.

Both outbound dialing and `wd-agent` listener/accept paths are implemented. `wd-agent serve --rfcomm-channel N` binds the configured channel and feeds accepted connections into the normal listener supervisor and `session.Server.ServeConn` path.

## Windows implementation

Windows uses native Winsock Bluetooth sockets with `AF_BTH`, `SOCK_STREAM`, and `BTHPROTO_RFCOMM`. Both outbound dialing and listener/accept are implemented without shell helpers, SDP discovery, or an alternate trust path.

The Windows transport uses nonblocking sockets with bounded readiness polling so connection setup honors context deadlines and `net.Conn` read/write deadlines. Accepted connections are passed to the same `wd-agent` listener supervisor and `session.Server.ServeConn` path used by Linux and direct TCP.

`wd-agent serve --rfcomm-channel N` therefore enables the RFCOMM server path on both Linux and Windows. The channel remains explicit and is never inferred from Bluetooth pairing state or device metadata.

## Security boundary

Bluetooth pairing, link encryption, device names, MAC addresses, and physical proximity are not WeDecent identity authorization. They may provide transport-level protection, but WeDecent still requires:

- TLS 1.3;
- exact WeDecent device identity/fingerprint verification;
- the existing single-use pairing secret for first trust establishment;
- persisted WeDecent trust for later sessions; and
- the existing short-lived connection-grant authorization for terminal access.

A successful OS Bluetooth pairing does not create WeDecent trust. Conversely, an explicitly selected RFCOMM path never falls back to TCP, relay, or another transport after an RFCOMM failure.

## Client usage

Pair with an explicitly identified peer:

```text
wd pair --rfcomm 01:23:45:67:89:AB/7 --fingerprint <fingerprint>
```

Connect to an already paired device while overriding its stored locator:

```text
wd connect --rfcomm 01:23:45:67:89:AB/7 <device-id>
```

Normal account/connection-grant requirements still apply to terminal sessions.

## Linux hardware validation

`scripts/test-linux-rfcomm-hardware.sh` is a hardware-required client validation gate. It fails unless Linux has a powered BlueZ controller and the configured Bluetooth peer is already paired at the OS level. It then builds `wd`, performs a real WeDecent pair over RFCOMM, and optionally performs an authorized terminal session when a connection-grant file is supplied.

Required environment variables:

```text
WEDECENT_RFCOMM_PEER_MAC
WEDECENT_RFCOMM_CHANNEL
WEDECENT_RFCOMM_FINGERPRINT
WEDECENT_RFCOMM_PAIRING_SECRET
```

Optional terminal validation also uses `WEDECENT_RFCOMM_CONNECTION_GRANT_FILE`.

The Linux roadmap item remains incomplete until a successful authorized terminal run is recorded on real Bluetooth Classic hardware.

## Windows hardware validation

`scripts/test-windows-rfcomm-hardware.ps1` is the corresponding native Windows client gate. Run it with PowerShell 7 (`pwsh`) from the repository root on a Windows machine with a healthy Bluetooth adapter and an already OS-paired peer that is running a WeDecent RFCOMM listener on the configured channel.

Required environment variables:

```text
WEDECENT_RFCOMM_PEER_MAC
WEDECENT_RFCOMM_CHANNEL
WEDECENT_RFCOMM_FINGERPRINT
WEDECENT_RFCOMM_PAIRING_SECRET
```

The script builds `wd.exe`, requires a present healthy Windows Bluetooth device, performs a real RFCOMM pair, verifies that the trusted device persisted an `rfcomm://` locator, and emits:

```text
WEDECENT_WINDOWS_RFCOMM_PAIR_HARDWARE_OK
```

To run the authorized terminal gate as well, set:

```text
WEDECENT_RFCOMM_CONNECTION_GRANT_FILE
WEDECENT_RFCOMM_TERMINAL_INPUT_FILE
WEDECENT_RFCOMM_TERMINAL_MARKER
```

The terminal input file must cause the remote shell to print the expected marker without containing that marker contiguously itself. This prevents terminal/console echo from satisfying the assertion. For example, a Linux peer input can concatenate two quoted strings, while a PowerShell peer can concatenate two string literals.

A successful authorized terminal gate emits:

```text
WEDECENT_WINDOWS_RFCOMM_TERMINAL_SESSION_HARDWARE_OK
```

### Validating the Windows listener direction

The PowerShell harness proves the native Windows outbound dialer. To validate the Windows listener on hardware, reverse the topology:

1. On the Windows endpoint, initialize an isolated non-production agent state and rotate a single-use pairing secret.
2. Start `wd-agent serve` with an explicit `--rfcomm-channel N` and the normal direct authorization configuration needed for an authorized terminal session.
3. From an already OS-paired Linux or Windows peer, run the corresponding RFCOMM pairing/terminal hardware gate against the Windows Bluetooth MAC and channel.
4. Record both the pair gate and authorized terminal gate evidence.

Do not add SDP publication or discovery merely to automate this procedure. Channel discovery/UX is a separate roadmap item and must not grant trust.

The Windows Bluetooth Classic roadmap item remains incomplete until a successful authorized terminal run involving a real Windows RFCOMM endpoint is recorded.
