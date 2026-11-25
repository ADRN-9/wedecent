# Windows service mode

## Security boundary

Install WeDecent under a dedicated standard Windows service account. The state directory must be a new, empty local fixed-volume directory. Its protected DACL is established for the service account, LocalSystem, and local Administrators before identity, pairing, recovery, audit, or service-log material is written.

The Windows Ed25519 identity is stored as a machine-scoped DPAPI blob (`identity.key.dpapi`). `CRYPTPROTECT_LOCAL_MACHINE` permits the dedicated service account to decrypt the blob after an elevated installer provisions the state directory. Machine-scoped DPAPI is not non-exportable key storage: a principal able to read the blob on the same machine may be able to request decryption. The protected directory ACL remains the access boundary. TPM/CNG-backed non-exportable Ed25519 keys are not implemented.

Existing non-empty state is rejected. The installer does not rewrite ACLs over existing identity keys, certificates, pairing credentials, trust anchors, audit logs, or recovery state. Existing installations require an explicit offline migration and re-enrollment procedure; post-hoc ACL repair does not retroactively protect exposed material.

## Recovery authority requirements

Every service installation requires an origin-only HTTPS recovery-authority URL, the exact SHA-256 leaf-SPKI pin, an independently provisioned primary/witness public trust JSON file, and a short-lived bearer credential supplied over standard input.

The bearer is never placed in command-line arguments or environment variables. The installer writes it once, with create-exclusive semantics, to `recovery-authority.token` inside the newly provisioned service state directory, then applies and verifies the service DACL. The service command line contains only the credential file path. The service validates the file as a bounded regular file with a restrictive ACL before reading it.

The bearer file is plaintext at rest; its protected NTFS DACL is the local access boundary, and local Administrators/LocalSystem remain trusted principals. The installer bounds token length and secures provisioning but does not parse bearer claims or enforce expiry. The authority/operator must issue a short-lived token and revoke or rotate it according to the authority's credential policy.

The supplied trust file is validated and copied byte-for-byte with create-exclusive semantics into `recovery-authority-trust.json` inside the new protected state directory. The source file is never modified. The service uses only this protected copy; existing trust material is never overwritten or silently migrated.

## Install

Run from an elevated PowerShell session after creating a dedicated standard account and granting it **Log on as a service**:

```powershell
.\wd-agent.exe service install `
  --account ".\WeDecentSvc" `
  --listen= `
  --web-relay=https://relay.wedecent.com `
  --pairing-recovery-authority-url=https://recovery.example.com `
  --pairing-recovery-authority-spki-sha256=<64-hex-leaf-SPKI-pin> `
  --pairing-recovery-trust=C:\ProgramData\WeDecent\recovery-trust.json `
  --pairing-recovery-authority-token-stdin
```

The installer prompts without echo for the bearer token when attached to a console. For unattended provisioning, supply it on standard input. If `--account-password-stdin` is also used, provide the account password first and bearer token second, each on its own line. Avoid shell history, environment variables, and temporary plaintext files for credentials.

The installer resolves the actual configured service SID and provisions a protected empty directory before creating the bearer credential. It does not create the Ed25519 identity or pairing secret. Those are initialized only after SCM starts the agent under the dedicated service account. The service verifies state ownership and ACLs before opening its log or loading identity material.

## Existing installation and migration

Non-empty state is rejected with an explicit offline-migration requirement. The installer does not replace or repair existing trust material. Migration requires a separate reviewed procedure that inventories identity, certificates, pairing credentials, recovery records, audit evidence, owner/DACL, ancestor path protections and DPAPI scope. If safe migration cannot be demonstrated, re-enroll into a newly provisioned service identity.

The DPAPI scope is machine-wide, not user-scoped. Existing user-scoped DPAPI identity blobs are rejected by the identity loader rather than silently reprotected with a different scope. The plaintext-to-DPAPI migration preserves the Ed25519 key only after verifying the protected copy; deletion of the plaintext file is not secure erasure of backups, snapshots, filesystem history or SSD remnants.

## Manage

```powershell
.\wd-agent.exe service status
.\wd-agent.exe service stop
.\wd-agent.exe service start
.\wd-agent.exe service uninstall
```

## Remaining Windows limitations

- Native privileged installation and service startup under a distinct service SID require a controlled Windows VM; unit tests cannot substitute for this evidence.
- DPAPI machine-scope remains a compatibility protection, not TPM/CNG non-exportable key storage.
- Ancestor rename/delete-child races and path substitution remain independent security-review gates.
- The service log remains a protected local text file, not Windows Event Log.
