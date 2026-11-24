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

AuthorizationIssuer accepts a crypto.Signer rather than private-key byte slices, generates a 128-bit random JTI and caps capability lifetime at 120 seconds. The signer derives its key ID from the Ed25519 public key and verifies the signature against that key before returning a capability. The verifier checks canonical signature/JTI encodings, key ID, signature, exact claims, expiry and atomic replay consumption. FileReplay now persists per-device JTI state under a cross-process file lock and atomic replacement; NewPersistentAuthorizationVerifier wires it to an endpoint public key. Local Core production forwarding requires an explicitly constructed RemoteReplay verifier. FileReplay is available only through the explicit ManagerConfig.AllowFileReplay test/development opt-in; Local Core never sets that option. MemoryReplay remains for tests/development only. Each endpoint consumes the JTI through the independent replay authority under its own cryptographic device ID. The hosted ledger is shared infrastructure, but replay generations and consumed JTIs remain partitioned per device; one endpoint's replay namespace must never be substituted for another device's identity.

## Local Core lifecycle

coreprocess.Config.Forwarding can compose a forwarding manager into the Local Core runtime. It is optional and disabled unless configured. When no custom verifier is supplied, ReplayPath plus AuthorizationPublicKey configure the persistent device-scoped verifier; coreprocess supplies a default state-directory replay path when the public key is present. coreprocess also supplies its persisted trusted-devices store as the peer TrustChecker. The manager checks peer trust before starting and polls active/pending forwards; removal or an unreadable trust store invokes Manager.RevokeDevice and closes the parent session and child streams. Manager construction requires a Local Core PermissionAuthorizer that checks the exact port_forward.local or port_forward.remote grant; terminal.connect and mesh.forward are never substitutes. The manager owns listener creation, authorization, connection limits, child connection lifecycle, cancellation, revocation and audit writes. Device revocation also cancels in-flight start reservations. The desktop renderer is not given socket or destination-dialing APIs.

Local and remote listeners default to loopback through DefaultListenerPolicy. Non-loopback or privileged listeners require the separate ListenerAuthorizer seam; a signed forwarding capability alone cannot grant public exposure. Listener bind addresses must be literal canonical IPs; wildcard, link-local and invalid exposure combinations fail closed.

The Connector seam now opens one authenticated parent forwarding session with the complete signed Authorization, including the independent route authorization when a router is present. The capability is consumed once per endpoint session; each accepted TCP connection is a child stream authorized by that parent session rather than a replay of the same single-use token. ForwardingSession.OpenChild multiplexes those child streams, and Close terminates them. DestinationSession now checks the Local Core destination device ID and the direction-correct authenticated endpoint peer ID independently of any router. AuthenticatedPeerID must be the remote endpoint TLS certificate identity for that forwarding direction (the initiating device for local forwarding, the remote listener device for remote forwarding); routed sessions additionally require AuthenticatedRouterID to match the capability router and RouterTrustChecker to approve it in the separate routing trust domain. A trusted router is never accepted as a substitute for the initiating endpoint. The destination verifies endpoint trust and router trust separately before consuming the endpoint forwarding capability. The initiating Local Core manager performs the same separate endpoint/router trust checks before consuming its grant, watches both stores, and revokes active/pending forwards when either trust domain is removed or unreadable. It enforces the dedicated permission, pins the approved DNS/IP result, dials only approved IP literals, enforces signed maximum duration and signed per-child idle timeout, bounds child concurrency, and audits child lifecycle. The session context inherits authenticated parent transport cancellation so disconnect/cancellation closes all pending and active children. For routed paths it checks route-capability binding; the router must independently verify and consume mesh.RouteAuthorization. The actual TLS typed-stream wire adapter and client-side stream multiplexer are not yet connected, so this session engine is not yet reachable over a real two-device connection.

### Local Core source-side replay authority and endpoint trust

When Local Core forwarding is enabled, `wd-core` loads the existing device identity once and uses its Ed25519 signer to construct `RemoteReplay`. It combines that replay store with the separately provisioned port-forward authorization public key and injects the resulting `AuthorizationVerifier` explicitly into `ManagerConfig`. Local Core requires both `--port-forward-replay-url` and a public Data API key (`--port-forward-replay-api-key`, `WEDECENT_PORT_FORWARD_REPLAY_API_KEY`, or `WEDECENT_SUPABASE_ANON_KEY`). The account session's Supabase URL is never used to select the replay authority.

The replay authority hostname and SPKI SHA-256 pins are release trust anchors embedded in both `wd-core` and `wd-agent`, not values read from account sessions or mutable service-account JSON. Release builds must set:

```text
-X wedecent.com/wedecent/internal/portforward.replayAuthorityHostname=<canonical-lowercase-hostname>
-X wedecent.com/wedecent/internal/portforward.replayAuthoritySPKISHA256=<sha256-spki-hex>[,<next-sha256-spki-hex>]
```

The Windows release builder accepts `WEDECENT_REPLAY_AUTHORITY_HOSTNAME` and `WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256` and appends these linker settings to both endpoint binaries. Production release invocations must also set `WEDECENT_REQUIRE_REPLAY_AUTHORITY_TRUST=1`, which makes missing trust anchors a build failure. CI/diagnostic bundles may omit the values, but those binaries intentionally cannot enable port forwarding. Linux and macOS release builders must pass the equivalent linker flags.

The endpoint URL must use HTTPS, the exact embedded hostname, port 443 (implicit or explicit), and exactly `/functions/v1/port-forward-replay`; query strings, fragments, user information, alternate ports, redirects, and other hosts are rejected. Go's normal certificate-chain and hostname verification remain enabled, TLS 1.3 is mandatory, and the leaf certificate's DER SubjectPublicKeyInfo SHA-256 must match one of the embedded pins. At most four pins can be embedded for controlled overlap during rotation. Service-role and `sb_secret_` API keys are rejected; Local Core receives only a public Data API key.

**Pin rotation:** first release a binary containing both the current and next SPKI pins; rotate the authority certificate while both are accepted; then release a binary containing only the new pin. Hostname changes require a separately reviewed release trust-anchor update. Never rotate pins by editing service-account configuration.

Local Core rejects any existing local replay snapshot, marker, lock, anchor, pending transaction, or staging artifact before enabling remote replay. It does not migrate, delete, or silently ignore these files. Preserve an offline copy, revoke outstanding capabilities, and follow the identity-recovery procedure above. A same-account attacker may already have rolled back local replay history, so automatic migration is unsafe.

The unpinned `NewRemoteReplay` constructor is retained for isolated tests and development only. Production `wd-core` and `wd-agent` use `NewProductionRemoteReplay`; builds without embedded hostname and SPKI pins fail closed when forwarding is configured.

## Destination policy

ResolveApprovedDestination canonicalizes IPv4/IPv6 and DNS names, validates every DNS answer, rejects the entire answer set if any address is prohibited, and blocks loopback, link-local, multicast, unspecified, reserved, private-by-default and known cloud-metadata addresses. Private networks require explicit CIDR allowlists; ports require explicit ranges. The returned approval is sealed to its exact host, port, pinned IP set and policy so callers cannot mutate DNS results or substitute a broader policy before dialing. DialApprovedTCP dials only the approved IP literals and never resolves the hostname again.

DestinationSession invokes these helpers on the destination device before each child dial. The future authenticated typed-stream adapter must pass the direction-correct end-to-end endpoint TLS peer certificate ID as AuthenticatedPeerID. It must pass the independently authenticated router TLS certificate ID as AuthenticatedRouterID. Each ID must be verified against its own trust store; transport addresses or relay metadata must never populate either field.

## Audit and failure handling

Forward start and child-open audit records are durable prerequisites: if they cannot be appended, the listener or child connection is not made usable. Child closure records failed outcomes when the underlying connection close fails; parent cleanup aggregates listener, child and session close errors. Trust watcher failures are retained and returned from Manager.Close instead of being discarded. Stop, expiry, device revocation and child cleanup close resources before returning. Audit records contain forwarding ID, direction, endpoint device IDs and destination host/port, never payload bytes or capability signatures.

## Replay storage security

FileReplay requires an owned private state directory. Unix verifies the effective-user owner and enforces directory mode 0700 plus state, lock and anchor file mode 0600. Windows verifies the current-user owner and rejects DACL ACEs outside the current user, owner-scoped Creator Owner/Owner Rights, LocalSystem and Builtin Administrators. Windows also uses a persistent `.lock.bootstrap` coordination lock to serialize lock-file publication and cleanup of store-specific lock-bootstrap staging files; cleanup holds both the bootstrap and replay locks. If the creator crashes after `CREATE_NEW` but before owner assignment, the next process verifies the opened handle/path identity, regular-file type and restrictive DACL before repairing the owner. UnlockFileEx, handle-close and bootstrap-unlock failures are propagated as replay-unavailable errors instead of being discarded. The bootstrap lock is a coordination primitive, not a replay-history anchor.

The replay lock file and versioned generation anchor are permanent after initialization; deleting either, deleting both the state and lock while leaving the anchor, or deleting only the state fails closed. Existing C93 version-1 state is migrated once by anchoring its current generation. C94 version-2 state without its anchor is rejected. A separate generation anchor is fsynced before each state replacement; a stale state snapshot whose generation does not match the anchor is rejected. Rollback that occurred before the first C94 anchor migration cannot be detected retroactively. A crash between anchor and state publication can make replay unavailable, which is intentionally fail-closed.

The paired rollback regression `TestFileReplayPairedSnapshotAnchorRollbackDocumentsSameAccountGap` remains as historical evidence: restoring an older file snapshot and its matching anchor allows FileReplay to accept the old JTI again. FileReplay is therefore restricted to tests and explicitly local-only development; file permissions and Windows ACLs do not protect it from an attacker controlling the service account.

Both production endpoint paths require the independent `RemoteReplay` authority and have no file-backed fallback. Their HTTP clients require HTTPS with TLS 1.3, verify the configured hostname, enforce the release-embedded SPKI pin set, and refuse redirects. The endpoint sends the complete capability plus a device Ed25519 proof. The Edge Function independently verifies the control-plane capability signature, the enrolled endpoint device signature, endpoint membership, and device revocation state. Its service-role-only Postgres RPC atomically consumes a unique `(device_id,jti)`, increments a server-owned per-device generation, and advances a SHA-256 hash chain over the previous state, generation, JTI and exact capability digest. The authority state and ledger tables have RLS enabled and no direct table privileges for anon, authenticated or service_role; service_role can invoke only the append transaction. No reset/delete API is exposed. The database transaction is atomic: a lost response after commit causes a retry to be rejected as a duplicate, and authority unavailability fails closed.

This removes the local paired snapshot-and-anchor rollback path from the production verifier: restoring local replay files cannot erase the remote ledger. The control-plane administrator/database superuser and Edge Function service-role environment remain trusted infrastructure; compromise of those authorities is outside the local service-account threat model. The remote ledger currently retains entries indefinitely; safe compaction requires a separately reviewed proof that expired capabilities can no longer be accepted.

Existing local replay artifacts cannot be imported automatically. The agent rejects an existing file, marker, lock, anchor, pending transaction or store-specific staging file rather than assuming that its replay history is intact. Recovery requires stopping the agent, preserving an offline copy, revoking outstanding capabilities, and rotating/re-enrolling the endpoint identity under an operator-approved procedure. A same-account attacker may already have rolled back the local history, so automatic migration is not a security-preserving option.

### Administrative recovery for an interrupted initialization

A published `.lock` with no `.init` marker is not by itself proof that replay history exists. Recovery is deliberately operator-controlled:

1. Stop the WeDecent agent/service and verify that no agent process using this state directory remains. Do not perform recovery while the service can restart or another process can access the store.
2. Make an offline copy of the entire state directory before inspection. Preserve timestamps, ACLs/ownership, and every replay file.
3. If `.init`, replay state (`portforward-replay.json`), `.anchor`, or `.pending` exists, do not delete, rename, or recreate any of them. Treat the store as potentially containing replay history. Restore a complete, mutually consistent trusted backup of the whole replay store, or revoke outstanding capabilities and provision a new endpoint identity/state under a separately approved recovery plan. Do not use the legacy migration flag to bypass this condition.
4. Only when the marker, state, anchor, and pending transaction are all absent—and the only replay artifact is the published `.lock`—the interrupted operation could not yet have consumed a JTI. With the service stopped and the offline copy retained, move `.lock` to a clearly named quarantine file (do not destroy it), then restart the service so it can create a fresh lock and initialization marker.
5. On Windows, leave `.lock.bootstrap` in place. It serializes lock publication; it is not replay history and must not be removed as part of this recovery. If it is absent, allow the agent to create it through its serialized bootstrap protocol; do not create or replace it manually. If its ACL verification fails, preserve the directory and investigate rather than broadening its ACL.

If any artifact is malformed, ownership/ACL verification fails, or the file set is ambiguous, stop and fail closed. Never reset replay state by deleting individual files. The older unscoped Windows temporary names `.portforward-lock-*` from pre-store-scoped releases are intentionally not swept automatically: their store ownership and active-process status cannot be established from their filename. Preserve them during routine startup; any manual quarantine must follow the stopped-service/offline-copy procedure and must not be performed while an older agent process may still be running.

## Staging routed-terminal workflow

The manual staging routed-terminal E2E workflow pins checkout and Go setup actions to immutable commit SHAs, disables persisted checkout credentials, and only executes the job when dispatched from the protected `main` ref. Checkout is pinned to `refs/heads/main`. The staging environment and staging-only secrets remain unchanged; the production project guard remains fail-closed.

## Signing-key boundaries

The route-authorization Edge Function now imports its Ed25519 private key as a non-extractable WebCrypto key. A separately provisioned raw 32-byte Ed25519 public key (WEDECENT_ROUTE_AUTHORIZATION_PUBLIC_KEY_B64URL, unpadded base64url) determines the JWK-thumbprint kid and is used to prove private/public correspondence before issuance. The existing WEDECENT_ROUTE_AUTHORIZATION_PKCS8_B64 remains a secret input; non-extractable import does not turn an environment-provided PKCS8 secret into an HSM key.

Port-forward authorizations use a distinct signing domain and must have a separately provisioned key. Do not reuse the route-authorization, device-identity or router-administration signing keys. Production requires a non-exporting crypto.Signer provider and separate public-key provisioning at both endpoints; no private key is stored in this repository.

## Not yet production complete

- Hosted deployment and production provisioning of the independent replay authority remain outstanding. The Edge Function and append-only Postgres migration are repository artifacts; hosted deployment has not been verified. Deployment must apply `20261123080000_port_forward_replay_authority.sql`, deploy `port-forward-replay` with JWT verification disabled, and provision `WEDECENT_PORT_FORWARD_AUTHORIZATION_PUBLIC_KEY_B64URL` plus the server-side Supabase service-role key in the Edge Function environment only. The production project hostname and leaf SPKI pin must be independently verified and embedded in both endpoint binaries using the linker variables above. Endpoint processes receive only the public Data API key. Until hosted deployment, exact endpoint trust-anchor provisioning, and a persistent-authority integration test are verified, forwarding fails closed and is not production-ready. Existing file-backed replay stores require explicit identity recovery; no automatic migration is provided.
- Authenticated TLS typed-stream wire handling, server-side destination open/dial dispatch and client-side multiplexed stream support. DestinationSession and parent/child authorization lifecycle remain package APIs and are not connected to the session protocol or a real two-device E2E.
- Router-admin adapter wired to the separate router-admin trust store; public listeners remain unavailable until it is configured.
- Endpoint peer revocation and source-router trust revocation are detected by separate Local Core trust-store pollers and invoke Manager.RevokeDevice. DestinationSession independently polls its endpoint and router trust domains. Router-administration trust and transactional revocation events still require separate event hooks/watchers. Polling intervals are bounded but are not instantaneous transactional revocation events.
- Local Core now exposes narrowly scoped `port_forward.start`, `port_forward.stop`, `port_forward.status` and `port_forward.list` IPC operations through a typed service. Start accepts only the signed authorization object; no caller-supplied destination, listener address or raw dial operation is exposed. The desktop UI and real two-device direct/routed E2E across two Local Core instances remain unimplemented.
- Production provisioning of the separate port-forward signing public/private key pair and a non-exporting signing provider.

This batch is a foundation, not a claim of usable or production-ready port forwarding.


## C142 — atomic multi-participant Supabase authorization

The replay Edge Function now verifies the separate signed mesh.forward route authorization for routed capabilities. It requires the dedicated route-authorization public key and verifies the exact route ID, source, destination, router, hops, transports, costs and expiry. A routed capability without this independent signature fails closed.

The database transaction consume_port_forward_authorization now binds one forwarding_id and JTI to:
- the initiating device, destination device and optional router;
- each participant's current owner/account, organization and monotonic revocation epoch;
- the capability direction and distinct port_forward.local / port_forward.remote permission;
- current organization membership and explicit device-access grants;
- the independent route-authorization grant ID/JTI for routed forwarding;
- the signed authorization digest, issued time and expiry.

The transaction re-reads and locks the participant records before committing. Its lock order is organization rows, subject membership rows, subject device-access rows, route authorization row, then participant device rows in canonical device-ID order. Device membership and access mutation triggers advance the affected device epochs while holding the mutated membership/access row. Device owner, organization, key, kind and revocation changes advance the same device epoch.

The primary SQL transaction commit is the authorization/replay linearization point. A retry with the same forwarding ID, JTI, digest and participant snapshot returns the prior success without advancing replay state. Reuse of a forwarding ID with changed authorization context, or reuse of a JTI with a different forwarding ID, is rejected. Both endpoint devices may consume the same exact transaction once in their independent per-device replay ledgers.

The Edge Function still verifies the local device Ed25519 proof against the enrolled public key. The SQL RPC receives that public key and compares it against the same locked device row, preventing a pre-read key from being substituted between proof verification and consumption.

### Explicit boundaries

- The SQL transaction serializes only the Supabase primary database. It does not make witness commitment, acknowledgement, primary consumption and revocation atomic across independent services.
- The independent route grant is locked and checked for current revocation and exact participant binding. The route authorization signer remains a separate trust domain.
- The transaction records database-derived account, organization and revocation snapshots. The existing port-forward capability wire profile does not yet carry those database snapshot fields as signed claims; authorization is therefore re-evaluated against current database state at each endpoint consumption.
- The pgTAP suite exercises sequential authorization, replay, rollback, revocation and membership/access mutation behavior. It does not prove concurrent safety across independent database sessions. A barrier-controlled two-session race suite is still required.
- Production application of the migrations, Edge Function deployment, route and port-forward public-key provisioning, and independently administered witness integration remain separate gates. No hosted production deployment is claimed.
