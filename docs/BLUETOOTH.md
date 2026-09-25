# Bluetooth RFCOMM transport

Phase 3 begins with a Linux Bluetooth Classic RFCOMM client dialer in `internal/transport`.

## Locator format

The dialer accepts an explicit locator only:

```text
XX:XX:XX:XX:XX:XX/CHANNEL
```

`CHANNEL` must be canonical decimal `1` through `30`. The MAC address must use six colon-separated hexadecimal octets. Lowercase hexadecimal is accepted and canonicalized to uppercase.

Example:

```text
01:23:45:67:89:AB/7
```

The implementation uses the Linux `AF_BLUETOOTH` / `BTPROTO_RFCOMM` socket API through the repository's already-pinned `golang.org/x/sys/unix` dependency. It does not execute `bluetoothctl`, `rfcomm`, shell commands, or PATH-resolved helpers, and it does not add CGO or a dynamic BlueZ-library dependency.

## Security boundary

Bluetooth pairing and link encryption are not treated as WeDecent identity authorization. RFCOMM only supplies a byte stream implementing the existing `transport.Conn` boundary. TLS 1.3, exact device identity/fingerprint checks, terminal authorization, routing authorization, and all higher-level protocol limits remain unchanged above the transport.

The RFCOMM client requires an explicit MAC address and channel. It performs no Bluetooth discovery, SDP lookup, trust inference, or TOFU.

Dialing is context-bounded and uses a nonblocking socket. File-descriptor ownership remains local to the transport and is closed on failed connection setup.

## Current scope

This first slice implements the Linux outbound dialer and strict locator parsing only. The Phase 3 roadmap item remains incomplete until the agent-side listener/server path and hardware-backed integration coverage are added.

Planned follow-up work:

- Linux RFCOMM listener/accept path for `wd-agent`
- explicit configuration plumbing without exposing trust or TLS policy to the transport
- native Linux Bluetooth hardware/integration test where CI infrastructure permits it
- optional SDP/discovery UX as a separate layer; discovery must not grant trust
