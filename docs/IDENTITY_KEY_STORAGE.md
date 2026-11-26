# Identity private-key storage

WeDecent device identities use Ed25519. The public key determines the stable device ID and trust fingerprint, so storage migrations must preserve the exact private/public key pair.

## Windows

On Windows, `identity.key` plaintext PEM storage is migrated to a DPAPI-protected file named:

```text
identity.key.dpapi
```

New Windows identities also use that protected format. The payload contains PKCS#8 Ed25519 key material encrypted by Windows DPAPI with:

- `CRYPTPROTECT_LOCAL_MACHINE`, so service installation can provision the identity before SCM starts the dedicated service account;
- `CRYPTPROTECT_UI_FORBIDDEN`, so service and unattended startup never trigger credential UI.

Machine-scoped DPAPI is **not** the authorization boundary by itself. Any local principal that can read the ciphertext and call machine-scope DPAPI may be able to decrypt it. WeDecent therefore continues to rely on restrictive state-directory ACLs: per-user state remains user-protected by the filesystem, while Windows service state is restricted to the dedicated service account, LocalSystem, and local Administrators.

This is protection against plaintext private keys at rest; it is not a TPM/CNG non-exportable key implementation. The Phase 1.1 OS-keychain/TPM roadmap item remains open for stronger platform-backed/non-exportable storage and non-Windows coverage.

## Windows migration behavior

`identity.Ensure` performs migration only when it is already allowed to create or renew identity state:

1. If `identity.key.dpapi` exists, it is authoritative and must decrypt and parse successfully.
2. If both protected and legacy plaintext keys exist, their public keys must match. A mismatch fails closed.
3. If only legacy `identity.key` exists, WeDecent parses that same key, protects it with DPAPI, atomically publishes `identity.key.dpapi`, decrypts the new file to verify the same public key, and only then removes the plaintext file.
4. If neither file exists, WeDecent generates a new Ed25519 key and persists only the protected form.

A corrupt or undecryptable protected file never causes automatic key regeneration. Silent regeneration would rotate the device ID and invalidate trust pins.

`identity.Load` is deliberately non-mutating. It can load either the protected format or an older plaintext identity but does not create, migrate, delete, or renew identity material.

Deleting the old plaintext file after migration is **not secure erasure**. Previous bytes may remain recoverable from SSD behavior, filesystem history, backups, snapshots, or forensic copies. Operators with sensitive historical state should address those storage layers separately.

## Non-Windows platforms

Linux and other non-Windows builds currently retain the existing `0600` PKCS#8 PEM private-key file. OS keychain/TPM integration for those platforms is still pending.


## C314 — platform-backed Ed25519 signer architecture

### Current implementation boundary

The current Windows implementation stores PKCS#8 Ed25519 bytes protected by DPAPI in identity.key.dpapi. DPAPI machine scope enables service provisioning, but it is not a non-exportable key: the agent decrypts the key into process memory and uses it as an Ed25519 private key. The ACL on the service state directory remains the authorization boundary. The current non-Windows implementation stores PKCS#8 PEM in a 0600 file and loads the raw Ed25519 private key into process memory. Neither implementation is hardware-backed or non-exportable.

The existing code path is private-key-value oriented: loadOrCreatePrivateKey returns ed25519.PrivateKey. A platform-backed implementation cannot simply replace the file read with an OS keystore call while keeping this contract, because the private key must never be exported to satisfy the stronger requirement.

### Required signer abstraction

The certificate issuance boundary already accepts crypto.Signer, but the complete identity object and storage path are not yet provider-neutral: Identity.PrivateKey is still ed25519.PrivateKey, Ensure obtains raw bytes from loadOrCreatePrivateKey, and the current TLS certificate carries the raw key value. The required work is to extend the existing signer seam through the whole identity lifecycle rather than claim that the current seam alone completes the migration.

- The provider-neutral identity handle exposes the exact Ed25519 public key whose bytes determine the existing device ID and fingerprint.
- Sign accepts only Ed25519 signing options and returns a signature; unsupported algorithms/options fail closed.
- Close releases provider handles and zeroizes any transient buffers the provider returns.
- Key metadata exposes provider, algorithm, stable key handle/reference, protection class and public fingerprint, but never private key bytes or secret-bearing provider paths.
- LoadExisting must be non-mutating. Ensure may create or migrate only under its existing explicit lifecycle authorization.
- Identity.PrivateKey must no longer expose an exportable ed25519.PrivateKey on the provider-backed path. TLS certificate construction, challenge signing and identity proof must consume the signer handle without exporting key bytes.

The software-file and DPAPI implementations may temporarily adapt to the signer interface while retaining current behavior. Provider-backed signers must prove that private-key export is disabled by provider policy, not merely omit an export method from Go.

### Windows provider requirements

Microsoft's current Windows native-cryptography documentation (as summarized in open Issue #84) states that Windows does not support EdDSA (Ed25519/Ed448); the documented built-in KSP algorithm sets cover RSA/ECDSA/ECDH, not Ed25519. The desired Windows backend is therefore conditional on a separately supported Ed25519-capable CNG/KSP or approved hardware provider, not an assumption that the Microsoft Platform Crypto Provider can do it. If no supported provider can create and use a persistent non-exportable Ed25519 key, retain the DPAPI implementation and keep this milestone open. The service opens the provider key at runtime and signs without receiving private bytes. Provisioning must occur under a controlled elevated installer/operator context, and service startup must independently verify provider, algorithm, public fingerprint, key ACL and expected key name.

Do not assume that a given Windows CNG/KSP, TPM, smart-card or HSM supports Ed25519. Capability must be established on the minimum supported Windows versions and the exact provider/firmware combination. A provider that supports only RSA or NIST ECDSA cannot be silently substituted: changing the identity algorithm changes public-key fingerprints, device IDs, certificate semantics and trust pins. If the platform provider cannot preserve the existing Ed25519 public key and sign with it non-exportably, retain the explicitly documented DPAPI fallback or block the stronger-storage acceptance milestone; do not regenerate or silently migrate identity.

The acceptance matrix must cover provider capability discovery, non-exportability/export rejection, signer-only operation under the service SID, denial to an ordinary user and unrelated service, stable fingerprint across service restart/reboot and installer migration, provider/key ACL tampering, missing provider/key, revoked/deleted key, and backup/restore recovery. Any missing or mismatched provider identity fails closed.

### Linux and macOS provider requirements

The Linux service backend must work without an interactive desktop session. A user-session Secret Service or D-Bus agent cannot be assumed to exist for a system service. Select a provider with a stable service identity, unattended unlock policy and enforceable per-service access control. Candidate integrations (for evaluation, not yet accepted) include a system daemon/keyring with service credentials or an Ed25519-capable PKCS#11 provider backed by a hardware token/HSM. A 0600 file remains the current fallback; it is not non-exportable.

The macOS backend must be evaluated separately from Linux. Keychain access control must bind to the signed WeDecent service/application identity and support unattended service operation. Secure Enclave or another hardware-backed provider must be proven to support the exact Ed25519 signing operation; do not infer Ed25519 support from generic Secure Enclave availability. A provider that only supports a different curve cannot replace the existing device identity.

For each OS, record the minimum OS version, provider and firmware version, algorithm support, whether key material can be exported, access-control principal, service unlock behavior after reboot, backup/restore semantics, hardware replacement behavior, and public fingerprint preservation. If an existing Ed25519 key cannot be imported into the selected provider without exporting it, the migration requires a separately approved identity re-enrollment with explicit device trust re-establishment; never silently create a replacement key.

### Identity migration and recovery invariants

1. Existing public key, device ID, certificate identity and fingerprint remain byte-for-byte stable during a storage-only migration.
2. New provider-backed storage is created and its signer operation is verified before the old protected/file key is retired.
3. Verify by signing a fresh random challenge and checking it against the expected existing public key. Do not compare only provider labels or key names.
4. The old private-key representation is retired only after provider persistence, service-context signing, restart/reboot continuity and recovery evidence pass. Deletion is not secure erasure; address snapshots/backups separately.
5. Missing provider, denied ACL, unsupported algorithm, changed public fingerprint, failed challenge, expired authorization or ambiguous provider selection stops startup. Never regenerate a new identity as fallback.
6. Recovery procedures must be tested on a disposable persistent VM/device image, including service-account migration and rollback, and must not copy plaintext private keys into issue comments, CI artifacts or support bundles.

### C314 status

No signer interface refactor, CNG/KSP adapter, Linux service keyring adapter or macOS Keychain adapter was implemented in this task. The design above preserves the existing Ed25519 identity invariant and gives each provider a measurable acceptance gate. Issues #84 (Windows TPM/CNG Ed25519) and #92 (non-Windows platform-backed storage) remain open and require provider capability evidence and named platform owners.
