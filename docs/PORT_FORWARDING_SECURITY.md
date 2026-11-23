# Secure TCP port forwarding — first implementation batch

Status: Local Core lifecycle and authorization foundations are implemented; forwarding is not yet enabled in the product UI or over the live typed-stream transport.

## Authorization contract

The internal/portforward package defines a separate Ed25519-signed capability profile. It is not a terminal grant and does not imply mesh.forward or router-administration permission. The canonical signed message is domain separated as wedecent-port-forward-v1 and binds:

- forwarding ID, direction, initiating and destination device IDs;
- optional router ID and the exact ordered route (ID, endpoints, hops, transports, costs and expiry);
- TCP protocol, destination host and port;
- exact listener address, port and exposure policy;
- issue/expiry times, single-use JTI and bounded connection/duration/idle limits.

For local forwarding the listener is on the initiating device and the route runs initiator-to-destination. For remote forwarding the listener is on the destination device and the route runs destination-to-initiator; the destination host/port is on the route's final endpoint. The listener endpoint is derived from the direction and checked against the Local Core identity. A routed path additionally requires a separately signed mesh.RouteAuthorization; the port-forward capability's route description is not itself a routing grant. Local Core checks that both capabilities bind the exact same route, while the router independently verifies and consumes the route capability under the routing trust domain.

AuthorizationIssuer accepts a crypto.Signer rather than private-key byte slices, generates a 128-bit random JTI and caps capability lifetime at 120 seconds. The signer derives its key ID from the Ed25519 public key and verifies the signature against that key before returning a capability. The verifier checks canonical signature/JTI encodings, key ID, signature, exact claims, expiry and atomic replay consumption. FileReplay now persists per-device JTI state under a cross-process file lock and atomic replacement; NewPersistentAuthorizationVerifier wires it to an endpoint public key. coreprocess defaults its replay path inside the Local Core state directory when a forwarding public key is supplied. MemoryReplay remains for tests/development only. Each endpoint consumes the JTI in its own Local Core store; replay state must not be shared globally between the two endpoint devices.

## Local Core lifecycle

coreprocess.Config.Forwarding can compose a forwarding manager into the Local Core runtime. It is optional and disabled unless configured. When no custom verifier is supplied, ReplayPath plus AuthorizationPublicKey configure the persistent device-scoped verifier; coreprocess supplies a default state-directory replay path when the public key is present. coreprocess also supplies its persisted trusted-devices store as the peer TrustChecker. The manager checks peer trust before starting and polls active/pending forwards; removal or an unreadable trust store invokes Manager.RevokeDevice and closes the parent session and child streams. Manager construction requires a Local Core PermissionAuthorizer that checks the exact port_forward.local or port_forward.remote grant; terminal.connect and mesh.forward are never substitutes. The manager owns listener creation, authorization, connection limits, child connection lifecycle, cancellation, revocation and audit writes. Device revocation also cancels in-flight start reservations. The desktop renderer is not given socket or destination-dialing APIs.

Local and remote listeners default to loopback through DefaultListenerPolicy. Non-loopback or privileged listeners require the separate ListenerAuthorizer seam; a signed forwarding capability alone cannot grant public exposure. Listener bind addresses must be literal canonical IPs; wildcard, link-local and invalid exposure combinations fail closed.

The Connector seam now opens one authenticated parent forwarding session with the complete signed Authorization, including the independent route authorization when a router is present. The capability is consumed once per endpoint session; each accepted TCP connection is a child stream authorized by that parent session rather than a replay of the same single-use token. ForwardingSession.OpenChild multiplexes those child streams, and Close terminates them. DestinationSession now checks the Local Core destination device ID and the authenticated peer device ID, verifies that peer in the corresponding trust domain, independently verifies and consumes the forwarding capability, enforces the dedicated permission, pins the approved DNS/IP result, dials only the approved IP literals, applies connection and lifetime limits, polls peer trust for active-session revocation, and audits child lifecycle. For routed paths it checks the route-capability binding; the router must independently verify and consume mesh.RouteAuthorization. The actual TLS typed-stream wire adapter and client-side stream multiplexer are not yet connected, so this session engine is not yet reachable over a real two-device connection.

## Destination policy

ResolveApprovedDestination canonicalizes IPv4/IPv6 and DNS names, validates every DNS answer, rejects the entire answer set if any address is prohibited, and blocks loopback, link-local, multicast, unspecified, reserved, private-by-default and known cloud-metadata addresses. Private networks require explicit CIDR allowlists; ports require explicit ranges. The returned approval is sealed to its exact host, port, pinned IP set and policy so callers cannot mutate DNS results or substitute a broader policy before dialing. DialApprovedTCP dials only the approved IP literals and never resolves the hostname again.

DestinationSession invokes these helpers on the destination device before each child dial. The authenticated typed-stream adapter must pass the TLS peer certificate device ID as AuthenticatedPeerID; transport addresses or relay metadata must never populate this field.

## Audit and failure handling

Forward start and child-open audit records are durable prerequisites: if they cannot be appended, the listener or child connection is not made usable. Stop, expiry, device revocation and child cleanup close resources before returning. Audit records contain forwarding ID, direction, endpoint device IDs and destination host/port, never payload bytes or capability signatures.

## Signing-key boundaries

The route-authorization Edge Function now imports its Ed25519 private key as a non-extractable WebCrypto key. A separately provisioned raw 32-byte Ed25519 public key (WEDECENT_ROUTE_AUTHORIZATION_PUBLIC_KEY_B64URL, unpadded base64url) determines the JWK-thumbprint kid and is used to prove private/public correspondence before issuance. The existing WEDECENT_ROUTE_AUTHORIZATION_PKCS8_B64 remains a secret input; non-extractable import does not turn an environment-provided PKCS8 secret into an HSM key.

Port-forward authorizations use a distinct signing domain and must have a separately provisioned key. Do not reuse the route-authorization, device-identity or router-administration signing keys. Production requires a non-exporting crypto.Signer provider and separate public-key provisioning at both endpoints; no private key is stored in this repository.

## Not yet production complete

- Control-plane durable issuance, key provisioning, revocation/expiry outbox integration and production replay-state backup/retention. AuthorizationIssuer and FileReplay are implemented as package APIs, but production key provisioning and a managed issuer service are not integrated. FileReplay has not yet been verified by exact-HEAD CI.
- Authenticated TLS typed-stream wire handling and client-side multiplexed stream support. DestinationSession and the parent/child authorization lifecycle are implemented as package APIs, but they are not yet connected to the session protocol or a real two-device E2E.
- Router-admin adapter wired to the separate router-admin trust store; public listeners remain unavailable until it is configured.
- Trust-revocation hooks wired from every device-trust mutation path into Manager.RevokeDevice.
- IPC methods, desktop UI, E2E tests across two Local Core instances and route relay, and production policy configuration.
- Production provisioning of the separate port-forward signing public/private key pair and a non-exporting signing provider.

This batch is a foundation, not a claim of usable or production-ready port forwarding.
