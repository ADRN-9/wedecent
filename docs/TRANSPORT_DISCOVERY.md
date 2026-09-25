# Transport discovery and pairing UX contract

## Purpose

Transport discovery exists to help an operator locate a WeDecent endpoint. It does not establish WeDecent identity or trust.

A discovered IP address, Bluetooth address, RFCOMM channel, serial device, USB descriptor, device name, advertisement, or other link-layer metadata is a routing hint only. The authenticated session layer remains authoritative.

## Trust boundary

Any discovery or selection UX must preserve these invariants:

- the operator must provide or independently verify the expected WeDecent fingerprint before first pairing;
- a discovery result must never be promoted into terminal trust automatically;
- OS Bluetooth pairing is not WeDecent authorization;
- USB enumeration or physical attachment is not WeDecent authorization;
- device IDs, names, MAC addresses, IP addresses, PSMs, channels, VID/PID values, serial numbers, and proximity are not sufficient trust evidence;
- terminal trust, routing trust, and router-administration trust remain separate;
- discovery must not create routing authority;
- explicit transport selection must fail closed and must never fall back to another transport after malformed input or connection failure.

Signed LAN advertisements prove possession of the advertised key. They do not prove that the key belongs to the endpoint the operator intended to trust. The displayed fingerprint is therefore useful for comparison with an independently obtained expected fingerprint, not as an automatic trust source.

## UX rules

A future transport picker should present candidates as untrusted connection hints until they match existing pinned trust or the operator verifies the expected fingerprint through an independent channel.

For an unpaired endpoint, the UX should:

1. show the candidate transport and locator separately from identity information;
2. label discovery-derived identity/fingerprint data as untrusted until independently verified;
3. require an expected WeDecent fingerprint before the pairing attempt;
4. require the normal single-use pairing secret;
5. send the selected byte stream through the existing `session.Client` TLS/pinning path; and
6. persist trust only after the normal pairing protocol succeeds.

For an already paired endpoint, discovery may improve path selection only after matching the discovered device identity to the stored pinned fingerprint. A mismatch must fail closed and must not silently try another candidate with the same device ID.

## Candidate ambiguity

Discovery can return stale, duplicate, spoofed, or conflicting candidates. The UX must not guess.

- Multiple candidates for an unpaired endpoint require explicit operator selection.
- Multiple candidates claiming the same device ID but different fingerprints are a security error.
- A candidate for a paired device with a fingerprint different from stored trust is a security error.
- Unsupported or malformed locators are errors, not fallback triggers.
- Discovery timeouts return no candidate rather than silently changing transport policy.

## Transport-specific guidance

### LAN

Signed multicast discovery may advertise a direct TCP endpoint, device ID, name, and fingerprint. Treat the endpoint as a routing hint. For paired devices, the existing trusted-LAN path may be selected only after exact fingerprint matching and a successful authenticated probe.

### Bluetooth RFCOMM

Do not infer a WeDecent peer from a Bluetooth device name or OS pairing state. A picker may enumerate nearby or paired Bluetooth devices for operator convenience, but the RFCOMM address/channel remains only a locator. Automatic SDP/channel discovery, if added, must not change identity or authorization semantics.

### USB CDC-ACM

A picker may enumerate candidate serial devices, but `/dev` path, USB VID/PID, product name, serial number, bus path, and physical attachment remain locator metadata only. The selected stream must still pass through normal TLS fingerprint verification and pairing authorization.

### USB networking

Interface identity, USB MAC addresses, and point-to-point IP addresses remain transport metadata. Use the existing pinned direct-TCP path.

## CLI direction

The current `wd discover` command should remain safe to script. Any future richer discovery command or interactive picker should keep machine-readable locator data distinct from trust decisions.

Pairing help and errors must not imply that a discovery result by itself is an acceptable source of the expected fingerprint. Recommended wording should direct operators to verify the fingerprint through a trusted independent channel, such as local `wd-agent identity` output or managed enrollment data.

## Completion criteria

The roadmap parent item `Pair/transport discovery UX` remains incomplete until executable client UX implements these rules with deterministic tests. Documentation of this contract is only the first slice.
