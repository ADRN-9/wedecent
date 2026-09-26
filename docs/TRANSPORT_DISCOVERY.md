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

First-pair LAN discovery is available explicitly through:

```text
wd pair --discover-lan --device-id wd_xxxxxxxxxxxxxxxx --fingerprint SHA256:<independently-verified-fingerprint>
```

The expected fingerprint must come from an independent trusted channel, such as local `wd-agent identity` output on the target machine or authenticated managed enrollment data. Do not copy the discovery-advertised fingerprint into `--fingerprint` merely because it was discovered on the LAN.

`--discover-lan` observes the full bounded discovery window before selecting a candidate. Exact duplicate advertisements are harmless, but distinct valid endpoints for the same target are treated as ambiguous and fail rather than selecting the first packet. A matching device ID with a conflicting fingerprint is a hard identity error.

The discovery window defaults to 6 seconds and can be changed with `--discover-timeout`, up to 1 minute. `--discover-timeout` is valid only with `--discover-lan`. LAN discovery is mutually exclusive with `--endpoint`, `--rfcomm`, `--serial`, `--relay`, and `--web-relay`; it never falls back to one of those transports after failure.

After a single candidate is selected, the client converts only its direct IP/port into the existing `tcp://` locator and then runs the unchanged pairing path. The normal single-use pairing secret, TLS 1.3 identity verification, exact expected fingerprint, and successful pairing protocol remain required before trust is persisted.

### Bluetooth RFCOMM

Do not infer a WeDecent peer from a Bluetooth device name or OS pairing state. A picker may enumerate nearby or paired Bluetooth devices for operator convenience, but the RFCOMM address/channel remains only a locator. Automatic SDP/channel discovery, if added, must not change identity or authorization semantics.

The current CLI intentionally keeps RFCOMM selection explicit rather than adding automatic Bluetooth enumeration or SDP selection. The existing `--rfcomm` locator is sufficient for the Phase 3 transport contract. A richer picker is deferred to the Phase 4 desktop product, where native platform APIs can present candidates visibly without treating pairing state, device name, address, or discovered channel as trust.

### USB CDC-ACM

A picker may enumerate candidate serial devices, but `/dev` path, USB VID/PID, product name, serial number, bus path, and physical attachment remain locator metadata only. The selected stream must still pass through normal TLS fingerprint verification and pairing authorization.

The current CLI intentionally keeps USB serial selection explicit through `--serial`. Cross-platform automatic serial enumeration is deferred to the Phase 4 desktop product so platform-native metadata can be presented as untrusted locator information instead of silently selecting a device from USB descriptors.

### USB networking

Interface identity, USB MAC addresses, and point-to-point IP addresses remain transport metadata. Use the existing pinned direct-TCP path.

## Deferred richer transport pickers

Bluetooth and USB auto-enumeration are not required to complete the Phase 3 security/transport work. They are deferred to the desktop UX rather than added as CLI auto-selection because the platform APIs and available metadata differ substantially and are easy to mistake for identity evidence.

Reopen richer transport picker work when at least one of these is true:

- the Phase 4 desktop shell is ready to show multiple native candidates and require explicit operator selection;
- a concrete hardware workflow cannot reasonably provide an explicit RFCOMM or serial locator;
- a platform provides a stable native enumeration API that yields a canonical locator without requiring trust inference; or
- measured usability evidence shows explicit locator entry is blocking the target deployment.

Any future picker must still display discovery metadata as untrusted, require independently verified identity for first pairing, reject conflicting candidates, and pass the selected stream through the existing TLS/session authorization path.

## CLI direction

The current `wd discover` command remains safe to script and continues to expose signed LAN advertisement data without creating trust. `wd pair --discover-lan` is the first executable selection UX and deliberately requires both an explicit target device ID and an independently verified expected fingerprint.

Future richer discovery commands or interactive pickers must keep machine-readable locator data distinct from trust decisions. Pairing help and errors must not imply that a discovery result by itself is an acceptable source of the expected fingerprint.

## Completion criteria

The Phase 3 `Pair/transport discovery UX` item is complete for the current CLI scope: the discovery/trust contract is documented, first-pair LAN selection is executable and fail-closed, and richer Bluetooth/USB enumeration is explicitly deferred to the Phase 4 desktop picker under the criteria above.
