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

coreprocess.Config.Forwarding can compose a forwarding manager into the Local Core runtime. It is optional and disabled unless configured. When no custom verifier is supplied, ReplayPath plus AuthorizationPublicKey configure the persistent device-scoped verifier; coreprocess supplies a default state-directory replay path when the public key is present. Manager construction requires a Local Core PermissionAuthorizer that checks the exact port_forward.local or port_forward.remote grant; terminal.connect and mesh.forward are never substitutes. The manager owns listener creation, authorization, connection limits, child connection lifecycle, cancellation, revocation and audit writes. Device revocation also cancels in-flight start reservations. The desktop renderer is not given socket or destination-dialing APIs.

Local and remote listeners default to loopback through DefaultListenerPolicy. Non-loopback or privileged listeners require the separate ListenerAuthorizer seam; a signed forwarding capability alone cannot grant public exposure. Listener bind addresses must be literal canonical IPs; wildcard, link-local and invalid exposure combinations fail closed.

The Connector seam receives the complete signed Authorization, including the independently signed route authorization when a router is present. It must open an authenticated WeDecent stream, preserve both capabilities and the forwarding ID, and honor context cancellation. The destination endpoint must independently verify the port-forward signature, local device identity and dedicated permission, then consume the port-forward JTI in its own device-scoped replay store. The router must independently verify and consume the separate mesh.RouteAuthorization; neither capability substitutes for the other. The destination-side typed-stream open/dial handler is not yet connected in this batch.

## Destination policy

ResolveApprovedDestination canonicalizes IPv4/IPv6 and DNS names, validates every DNS answer, rejects the entire answer set if any address is prohibited, and blocks loopback, link-local, multicast, unspecified, reserved, private-by-default and known cloud-metadata addresses. Private networks require explicit CIDR allowlists; ports require explicit ranges. The returned approval is sealed to its exact host, port, pinned IP set and policy so callers cannot mutate DNS results or substitute a broader policy before dialing. DialApprovedTCP dials only the approved IP literals and never resolves the hostname again.

The destination-side connector must invoke these helpers immediately before dialing. That integration remains a required follow-up; the listener manager cannot resolve a hostname on behalf of a different destination device.

## Audit and failure handling

Forward start and child-open audit records are durable prerequisites: if they cannot be appended, the listener or child connection is not made usable. Stop, expiry, device revocation and child cleanup close resources before returning. Audit records contain forwarding ID, direction, endpoint device IDs and destination host/port, never payload bytes or capability signatures.

## Signing-key boundaries

The route-authorization Edge Function now imports its Ed25519 private key as a non-extractable WebCrypto key. A separately provisioned raw 32-byte Ed25519 public key (WEDECENT_ROUTE_AUTHORIZATION_PUBLIC_KEY_B64URL, unpadded base64url) determines the JWK-thumbprint kid and is used to prove private/public correspondence before issuance. The existing WEDECENT_ROUTE_AUTHORIZATION_PKCS8_B64 remains a secret input; non-extractable import does not turn an environment-provided PKCS8 secret into an HSM key.

Port-forward authorizations use a distinct signing domain and must have a separately provisioned key. Do not reuse the route-authorization, device-identity or router-administration signing keys. Production requires a non-exporting crypto.Signer provider and separate public-key provisioning at both endpoints; no private key is stored in this repository.

## Not yet production complete

- Control-plane durable issuance, key provisioning, revocation/expiry outbox integration and production replay-state backup/retention. FileReplay is implemented as local durable replay storage but has not yet been run through exact-HEAD CI or two-device integration.
- Destination-side authenticated typed-stream open/dial handling, client-side multiplexed stream support and the single-use parent/child authorization lifecycle.
- Router-admin adapter wired to the separate router-admin trust store; public listeners remain unavailable until it is configured.
- Trust-revocation hooks wired from every device-trust mutation path into Manager.RevokeDevice.
- IPC methods, desktop UI, E2E tests across two Local Core instances and route relay, and production policy configuration.
- Production provisioning of the separate port-forward signing public/private key pair and a non-exporting signing provider.

This batch is a foundation, not a claim of usable or production-ready port forwarding.
