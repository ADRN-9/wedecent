# Windows installer

The first v0.3 installer layer is a PowerShell package around the reproducible Windows release bundle. It intentionally does not introduce MSI/WiX yet; the goal is to prove secure install, upgrade, rollback, reboot persistence, and uninstall semantics before freezing an MSI authoring model.

`installer/windows/Install-WeDecent.ps1` verifies the release executable checksums, installs the five Windows binaries under `C:\Program Files\WeDecent`, creates a dedicated standard local service account when needed, grants `SeServiceLogonRight`, and delegates identity creation, ACL hardening, SCM registration, and runtime configuration to `wd-agent.exe service install`.

Service-account passwords are not accepted on the command line. Installer metadata is written atomically with a hardened Administrators/SYSTEM ACL and is treated as untrusted if that protection is missing. For automated installation the installer passes the password through standard input to the Windows-only `--account-password-stdin` service-install option. Existing interactive behavior remains the default when that flag is absent.

Upgrades preserve the existing service account, SCM arguments, and `C:\ProgramData\WeDecent\agent` state. Binary replacement has a local rollback copy and restores the previous binaries if the upgraded service cannot start. Before service or file mutation, the installer fails closed if the installed same-user `wd-ui.exe` or `wd-core.exe` image is still running; it never kills those interactive processes.

Normal uninstall removes the service and program files but preserves the agent state and service account. Install and uninstall support a functional `-WhatIf` preflight; destructive paths are constrained to the WeDecent locations beneath Program Files and ProgramData and reparse-point traversal is rejected. `-Purge` explicitly removes the agent state. `-Purge -RemoveServiceAccount` additionally removes an account only when installer metadata proves that account was created/managed by this installer and its SID still matches.

Build the unsigned package after the release bundle:

```bash
make verify-release-windows
make release-windows
make installer-windows
```

The unsigned release is written to `dist/wedecent-windows-amd64/`. The unsigned installer package is written to `dist/wedecent-windows-installer/` and contains an outer `PACKAGE_SHA256SUMS.txt` in addition to the release bundle's executable `SHA256SUMS.txt`. The packaging script refuses output paths outside the repository `dist/` tree or paths that overlap the release input directory.

## Production Authenticode finalization

Reproducibility is checked on the unsigned build. Production signing is a separate, out-of-place finalization step so a signing failure cannot corrupt or replace the reproducible unsigned inputs.

Configure two absolute executable hooks:

- `WEDECENT_WINDOWS_AUTHENTICODE_SIGNER`: invoked as `signer <absolute-artifact-path>`. It must sign that file in place and return zero only on success.
- `WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER`: invoked as `verifier <absolute-artifact-path>`. It must return zero only when the artifact has an acceptable Authenticode signature under the release policy.

The finalizer passes only the artifact path. It does not interpolate a shell command, search `PATH`, accept certificate material, or pass credentials on a command line. The signing wrapper is responsible for using the organization-approved certificate source, HSM/key vault, timestamp service, and secret-injection mechanism. The verification wrapper should enforce the intended publisher identity, certificate-chain policy, Authenticode validity, and timestamp policy rather than merely checking that some signature blob exists.

Run:

```bash
export WEDECENT_WINDOWS_AUTHENTICODE_SIGNER=/absolute/path/to/wedecent-sign-wrapper
export WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER=/absolute/path/to/wedecent-verify-wrapper
make finalize-windows-signed
```

The finalizer validates the unsigned release/package manifests and requires the package copies to exactly match the release input. It also requires the five release executables and three packaged PowerShell scripts to fail the verifier before signing, preventing accidental re-signing of an already-finalized source tree.

Signing occurs only in a temporary output tree. The finalizer:

1. signs `wd.exe`, `wd-agent.exe`, `wd-routerctl.exe`, `wd-core.exe`, and `wd-ui.exe`;
2. verifies each signed executable;
3. regenerates the signed release `SHA256SUMS.txt`;
4. copies those exact signed executables and release metadata into the installer package;
5. signs `Install-WeDecent.ps1`, `Uninstall-WeDecent.ps1`, and `Test-WeDecentInstall.ps1` in the package copy;
6. verifies every signed executable and PowerShell script in the publishable tree;
7. regenerates `PACKAGE_SHA256SUMS.txt` from the final signed payload; and
8. publishes the complete signed tree only after all checks pass.

The default signed output is:

```text
dist/wedecent-windows-signed/
  release/
  installer/
```

The finalizer refuses to overwrite an existing signed output directory. The unsigned source directories remain byte-for-byte unchanged, preserving the reproducibility baseline and making signing retries explicit.

Canonical CI does **not** contain production certificates or signing credentials. It exercises the finalizer with fake signer/verifier fixtures to validate ordering, output isolation, manifest regeneration, exact payload handling, and failure behavior. Production distribution should use only the `installer/` payload produced by an organization-approved Authenticode signer/verifier pair.

Do not weaken Defender or PowerShell execution policy to compensate for unsigned, invalidly signed, or untrusted artifacts.

## Enroll a freshly installed agent in an account

A fresh Windows install creates the agent identity locally, but relay pairing requires
that identity to be enrolled in the WeDecent account first. Enrollment is deliberately
split so the account session remains on the authenticated client and the agent private
key remains on the agent machine.

1. On the agent machine, create a public enrollment request:

   ```powershell
   & 'C:\Program Files\WeDecent\wd-agent.exe' enrollment-proof `
       --request `
       --state 'C:\ProgramData\WeDecent\agent'
   ```

   Save the JSON as UTF-8 and transfer it to an authenticated client.

2. On the authenticated client, request the short-lived challenge:

   ```powershell
   wd account enroll-device --request-file .\agent-enroll-request.json
   ```

   Save the returned JSON as UTF-8 and transfer it to the agent machine.

3. On the agent machine, sign that challenge locally:

   ```powershell
   & 'C:\Program Files\WeDecent\wd-agent.exe' enrollment-proof `
       --state 'C:\ProgramData\WeDecent\agent' `
       --challenge-file .\agent-enroll-challenge.json
   ```

   Transfer the resulting proof JSON back to the authenticated client.

4. On the authenticated client, complete enrollment:

   ```powershell
   wd account enroll-device --proof-file .\agent-enroll-proof.json
   ```

Delete the temporary request/challenge/proof files after enrollment. They do not contain
the agent private key or account session credentials, but expired enrollment material
does not need to be retained.

After enrollment, relay pairing can request an account-authorized connection grant in
the normal way.
