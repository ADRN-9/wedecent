# C225 — relay handoff verification and Windows trust integration

## Relay protocol invariant

An outbound agent registration is authenticated by the Ed25519 signature over the relay challenge and device ID. The broker reserves capacity while the slot is not claimable. The relay writes TypeWaiting before activating the reservation.

While the slot is parked, the disconnect watcher owns the connection's read side. The agent MUST remain silent after TypeWaiting until it receives TypeReady from the relay during a claimed session. Any byte observed before handoff is an early-data protocol violation; the reservation is removed and the connection is closed. This avoids consuming application bytes that belong to a valid session.

Take removes one active slot from the broker and synchronously stops and joins the watcher before the bridge can use the connection. The watcher is interrupted with a read deadline. If it consumed any byte, observed EOF or another non-timeout read error during the handoff race, the claim fails closed. A clean timeout caused by the stop request is the only successful watcher termination.

The server then sends TypeReady to the agent before sending TypeReady to the client and starting the bidirectional bridge. No watcher may continue reading after this point.

This invariant is implemented in internal/relay/broker.go and exercised by broker and server tests. It is a protocol requirement for future relay transports and protocol versions, not an assumption that transport reachability proves device identity.

## C225 regression coverage

- Registration acknowledgement barrier: the reservation is not claimable until the acknowledgement write completes.
- Disconnect before activation and immediately after activation: observed disconnects remove the reservation and prevent claims.
- Handoff race: a byte consumed while the watcher is being stopped causes the claim to fail closed.
- End-to-end registration → waiting → connect → ready → application-data bridge: application bytes are preserved exactly.
- Premature application bytes before TypeReady: the parked connection is removed and a later connect receives unavailable.
- Initial server protocol reads: cancellation and timeout tests, including partial frame header and payload.
- Client protocol read stages: challenge for Dial/WaitRelaySession, connect Ready, registration Waiting and registration Ready; timeout and cancellation tests for each.
- Concurrent broker registration, activation, Take/connection handoff and reconnection stress under the race detector.
- Interrupted smoke process cleanup: cooperative and TERM-resistant child processes are terminated and waited/reaped by the cleanup trap.

The test suite uses controlled connections and synchronization channels rather than sleeps to coordinate race windows. CI results must be tied to the exact C225 head before any passing claim is made.

## PR #177 Windows state preflight versus PR #199 pairing/recovery

### Independently inspected source

- PR #177 head: b98b9f8c576305c8031a4d9b60d5f4fedcffcd27.
- PR #199 head: ff994121df8b3f0920e96f817e8c6aab47bb90e7.
- PR #177 is based on security/atomic-pairing-wd-c03; PR #199 is based on main. Their histories diverge. Do not merge one branch wholesale over the other.

### File-level overlap and conflicts

1. cmd/wd-agent/main.go: PR #177 adds preflightAgentState before init, pairing-secret, identity, enrollment-proof and agent startup. PR #199's current main.go contains recovery-authority configuration and client initialization plus port-forward settings, but none of those preflight calls. Replacing the PR #199 file with PR #177's copy would discard the newer recovery/forwarding integration. Correct integration is surgical: retain PR #199's configuration and authority wiring, and add the preflight before every state-writing or state-reading command that can expose secrets or trust state, especially before identity.Ensure in runAgent.

2. cmd/wd-agent/service_windows.go: PR #177 adds dedicated-service-SID provisioning before service installation, no-delete-sharing ancestor handles during service execution, state validation before logging, and protected first-create service-log handling. PR #199's current version instead creates identity/trust/pairing material under the elevated installer token and only then calls winservice.RestrictDirectory. Without a pre-create protected state boundary, that ordering can expose first-created material to inherited permissions. This is a security regression if the PR #199 ordering is retained without PR #177's preflight. Conversely, wholesale replacement with PR #177 would lose PR #199's pairing-secret onboarding/rotation flow. These flows must be reconciled deliberately, with protected directory creation before the first secret/key write and a documented service-account ownership transition.

3. internal/winservice/service_windows.go: PR #177 adds ResolveServiceAccountSID, used by service_state_windows.go; PR #199's current file has RestrictDirectory but not this resolver. The resolver must be ported without replacing PR #199's directory restriction implementation.

4. PR #177 adds state_preflight_windows.go, state_preflight_nonwindows.go, service_state_windows.go, their Windows tests, and the clients.go preflight calls. PR #199 does not contain these files. They depend on trust.VerifyPairingStatePath and the newer winservice.ResolveServiceAccountSID.

5. The PR #199 internal/trust/pairing_windows_security.go validator permits a narrowly controlled administrator/service-owner transition and validates the effective DACL against active and root-owner SIDs. PR #177's preflight uses this shared verifier after protected directory creation and before key/trust/pairing writes. The APIs are structurally compatible, but no combined Windows build or dedicated service-SID end-to-end run has yet been performed for this C225 candidate.

### Existing-state and upgrade boundary

PR #177's provisionWindowsServiceState requires an empty state directory before applying the dedicated service account's owner/DACL. That is fail-closed for a fresh install but rejects a non-empty existing installation. The service installer must not silently run it against an existing identity, trust store, pairing credential, or recovery ledger. A supported upgrade path needs to verify the existing exact service SID, path ancestry, DACL, reparse status and files without repairing them in place; otherwise require an explicit offline migration and re-enrollment. The December 1 legacy credential migration deadline must not be bypassed by filesystem ACL repair.

PR #177's handoff notes also identify unresolved Windows risks: ancestor DELETE_CHILD/rename and path substitution (WD-C32-01 HIGH), pairing-audit evidence deletion/acknowledgement (WD-C32-03 HIGH), and mixed-success first-run cleanup (WD-C32-04 MEDIUM). These require independent review and native privileged Windows testing; the preflight is not a complete resolution of those findings.

## Outstanding production dependencies

These are deployment/provider inputs, not repository code that can be safely fabricated:

1. Independent recovery authority and durable checkpoint storage. The client contract exists, but the separately administered production authority, transactional compare-and-advance service, durable anti-rollback checkpoint storage, backup/restore and fault-injection evidence remain outstanding.
2. Primary signing-key custody and independent witness provisioning. Non-exportable primary key custody, independently administered witness private keys/state, strict-majority quorum, anti-equivocation and independent recovery operators are not provisioned by this repository.
3. Production trust anchors and historical migration issuer. Production SPKI pins, public primary/witness trust file, device mTLS enrollment/tokens, key-rotation/revocation procedure and an issuer that authenticates historical archive/active-ledger provenance are external dependencies.
4. December 1, 2026 UTC legacy pairing migration. The cutoff is 2026-12-01 00:00:00 UTC. Production fleet inventory, agent-version/last-seen telemetry, per-device migration status, unreachable-device escalation and owner sign-off have not been supplied. Repository tests prove code paths, not fleet readiness.
5. Production signing and publication infrastructure. Protected GitHub release/signing/publication environments, independent reviewers, tag rules, production authority hostname/SPKI pins/approval digest, external signing identity and immutable stable-manifest publication must be configured and independently verified. No production private key or trust anchor is present in the repository.

## Evidence and limitations

Source comparisons and file contents were refreshed directly from GitHub. The previous C223 exact-head CI and Desktop results are historical only. No local Go execution, Windows service-account installation, real-hardware relay, independent authority deployment, production key provisioning, signing or publication is claimed by this document.
