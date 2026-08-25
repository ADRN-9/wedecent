# WeDecent Protocol v1

## Inner secure channel

Every terminal session uses TLS 1.3 with ALPN:

```text
wedecent/1
```

Agents and clients use self-signed Ed25519 identity certificates. Trust is SPKI pin based rather than Web PKI based. The client verifies the exact expected server public-key fingerprint. The agent requests a client certificate and verifies its public-key fingerprint against the local trusted-client store before starting a PTY.

Certificate validity is checked even though normal CA verification is intentionally replaced by pinning.

## Device ID

```text
wd_ + lowercase base32(SHA-256(Ed25519 public key)[0:10])
```

The current identifier therefore contains 80 bits derived from the key and is not a secret.

## Pairing

The agent creates a random 24-byte (192-bit) secret and stores only its SHA-256 hash.

The client must already know the expected device SPKI fingerprint. It establishes pinned TLS and sends:

```json
{
  "pairing_secret": "<secret>",
  "client_id": "wd_...",
  "client_name": "laptop"
}
```

The server validates that the TLS client certificate derives to `client_id`, consumes the pairing secret, persists the client fingerprint, and returns the server device identity. The client then persists the server fingerprint and locator.

A consumed secret cannot be reused; generate another with:

```bash
wd-agent pairing-secret
```

## Frame format

All values are network byte order.

```text
Offset  Size  Meaning
0       2     ASCII magic: WD
2       1     protocol version: 1
3       1     frame type
4       4     stream ID
8       4     payload length
12      N     payload
```

Maximum payload size: 1 MiB. Terminal data is emitted in chunks up to 32 KiB.

### Frame types

```text
1   PAIR_REQUEST
2   PAIR_RESPONSE
3   OPEN_SESSION
4   SESSION_ACCEPTED
5   DATA
6   RESIZE
7   CLOSE
8   ERROR
9   PING
10  PONG
```

Control messages use stream `0`. Terminal data currently uses stream `1`. The stream field is retained so later versions can multiplex terminals, file transfer and forwarding without replacing the frame header.

## Terminal session

The client sends `OPEN_SESSION`:

```json
{
  "cols": 120,
  "rows": 40,
  "term": "xterm-256color"
}
```

The client cannot specify an executable or command string. The agent starts only the shell configured by its operator.

After `SESSION_ACCEPTED`:

- `DATA` stream 1: raw PTY input/output bytes
- `RESIZE`: `{ "cols": 160, "rows": 50 }`
- `CLOSE`: session exit code / normal shutdown

Ctrl+C travels as the raw PTY byte `0x03`; it is not translated into a remote command API.

## Relay protocol

The relay connection is a separate TLS 1.3 channel using ALPN:

```text
wedecent-relay/1
```

Its certificate uses ordinary public Web PKI (or an explicitly configured private CA for development).

### Agent registration

1. Relay sends a random challenge.
2. Agent responds with device ID, Ed25519 public key and a signature over:

```text
wedecent-relay-register-v1 NUL challenge NUL device-id
```

3. Relay verifies the signature and verifies that the device ID derives from the supplied public key.
4. Relay parks the connection until a client requests that device.

This prevents a different key from registering itself as an existing device ID.

### Client connection

1. Client connects to the relay and receives a challenge.
2. Client requests a target device ID.
3. Relay takes one authenticated parked agent slot.
4. Relay sends `ready` to both sides and switches to blind byte forwarding.
5. Client and agent perform the **inner pinned TLS handshake through the relay**.

The relay cannot decrypt the inner session.
