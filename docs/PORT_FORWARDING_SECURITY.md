# Secure TCP port forwarding — first implementation batch

Status: Local Core lifecycle and authorization foundations are implemented; forwarding is not yet enabled in the product UI or over the live typed-stream transport.

## Authorization contract

The internal/portforward package defines a separate Ed25519-signed capability profile. It is not a terminal grant and does not reuse mesh.forward or router-administration trust. The canonical signed message is domain separated as wedecent-port-forward-v1 and binds:

- forwarding ID, direction, initiating and destination device IDs;
- optional router ID and the exact ordered route (ID, endpoints, hops, transports, costs and expiry);
- TCP protocol, destination host and port;
- exact listener address, port and exposure policy;
- issue/expiry times, single-use JTI and bounded connection/duration/idle limits.

For local forwarding the listener is on the initiating device and the route runs initiator-to-destination. For remote forwarding the listener is on the destination device and the route runs destination-to-initiator; the destination host/port is on the route's final endpoint. The listener endpoint is derived from the direction and checked against the Local Core identity.

The signer accepts crypto.Signer rather than private-key byte slices, derives its key ID from the Ed25519 public key and verifies the signature against that public key before returning a capability. The verifier checks the key ID, signature, exact claims, expiry and atomic replay consumption. MemoryReplay is explicitly for tests/development only; production must supply durable replay storage.

## Local Core lifecycle

coreprocess.Config.Forwarding can compose a forwarding manager into the Local Core runtime. It is optional and disabled unless configured. The manager owns listener creation, authorization, connection limits, child connection lifecycle, cancellation, revocation and audit writes. The desktop renderer is not given socket or destination-dialing APIs.

Local and remote listeners default to loopback through DefaultListenerPolicy. Non-loopback or privileged listeners require the separate ListenerAuthorizer seam; a signed forwarding capability alone cannot grant public exposure. Listener bind addresses must be literal canonical IPs; wildcard, link-local and invalid exposure combinations fail closed.

The Connector seam must open an authenticated WeDecent stream, preserve the forwarding ID and signed authorization at the destination endpoint, and honor context cancellation. The destination-side typed-stream open/dial handler is not yet connected in this batch.

## Destination policy

ResolveApprovedDestination canonicalizes IPv4/IPv6 and DNS names, validates every DNS answer, rejects the entire answer set if any address is prohibited, and blocks loopback, link-local, multicast, unspecified, reserved, private-by-default and known cloud-metadata addresses. Private networks require explicit CIDR allowlists; ports require explicit ranges. DialApprovedTCP dials only the approved IP literals and never resolves the hostname again.

The destination-side connector must invoke these helpers immediately before dialing. That integration remains a required follow-up; the listener manager cannot resolve a hostname on behalf of a different destination device.

## Audit and failure handling

Forward start and child-open audit records are durable prerequisites: if they cannot be appended, the listener or child connection is not made usable. Stop, expiry, device revocation and child cleanup close resources before returning. Audit records contain forwarding ID, direction, endpoint device IDs and destination host/port, never payload bytes or capability signatures.

## Signing-key boundaries

The route-authorization Edge Function now imports its Ed25519 private key as a non-extractable WebCrypto key. A separately provisioned raw 32-byte Ed25519 public key (WEDECENT_ROUTE_AUTHORIZATION_PUBLIC_KEY_B64URL, unpadded base64url) determines the JWK-thumbprint kid and is used to prove private/public correspondence before issuance. The existing WEDECENT_ROUTE_AUTHORIZATION_PKCS8_B64 remains a secret input; non-extractable import does not turn an environment-provided PKCS8 secret into an HSM key.

Port-forward authorizations use a distinct signing domain and must have a separately provisioned key. Do not reuse the route-authorization or device-identity signing keys.

## Not yet production complete

- Durable database issuance, single-use replay storage and revocation/expiry outbox integration for port-forward capabilities.
- Destination-side authenticated typed-stream open/dial handling and client-side multiplexed stream support.
- Router-admin adapter wired to the separate router-admin trust store; public listeners remain unavailable until it is configured.
- Trust-revocation hooks wired from every device-trust mutation path into Manager.RevokeDevice.
- IPC methods, desktop UI, E2E tests across two Local Core instances and route relay, and production policy configuration.
- Production provisioning of the separate port-forward signing public/private key pair and a non-exporting signing provider.

This batch is a foundation, not a claim of usable or production-ready port forwarding.
