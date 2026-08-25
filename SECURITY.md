# Security Notes

This repository is an early MVP and should receive an independent security review before privileged production deployment.

## Current protections

- TLS 1.3 only for terminal and relay TLS channels
- Ed25519 identities generated locally
- SPKI public-key pinning for device authentication
- Client public-key authorization at the agent
- 192-bit random, single-use pairing secrets; only hashes are stored
- 1 MiB protocol-frame hard limit
- Fixed operator-configured shell; clients cannot submit executable paths/command strings
- Agent direct connection concurrency limit
- Relay registration challenge signatures
- Relay per-device parked-slot cap and slot expiration
- Identity private-key files created with mode `0600`

## Known gaps before production

- No account-level RBAC or central revocation
- No persistent security audit store
- No relay IP/device rate limiter or abuse detection
- A client that knows a device ID can intentionally consume parked relay slots; inner authentication protects shell access, but targeted availability controls are still required
- No TPM/Secure Enclave/Windows CNG key storage
- No automatic relay certificate issuance/rotation
- No sandbox around the spawned shell; shell privilege equals the agent OS account
- No file-transfer path validation because file transfer is not implemented yet
- No fuzzing corpus/continuous fuzz infrastructure yet
- Linux-only PTY implementation

## Threat model note

The public relay is not trusted with terminal plaintext. It necessarily observes some metadata: requested device ID, connection timing, remote IP addresses and byte-flow characteristics. The inner pinned TLS session protects terminal content and client credentials from the relay.
