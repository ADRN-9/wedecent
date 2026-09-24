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
