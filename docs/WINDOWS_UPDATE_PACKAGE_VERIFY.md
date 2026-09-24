# Windows update package verification

This document defines the trust boundary between a staged Windows installer ZIP and the later installer-application step.

`updateinfo.WithVerifiedInstallerPackage` consumes an already-authenticated update manifest and a locally staged installer archive. It does not execute PowerShell, mutate installed files, stop or restart WeDecent processes, or advance `update-state.json`.

## Immediate verification boundary

The verifier deliberately uses a callback rather than returning a long-lived trusted directory. Before the callback runs it:

- revalidates the signed manifest;
- calls `VerifyStagedInstaller` again, so the archive bytes must still match `manifest.installer_sha256` immediately before package inspection;
- extracts into a new private temporary directory next to the staged archive;
- rejects archive members with paths, directories, duplicates, unexpected names, missing required files, zero-length members, or total expanded size above 1 GiB;
- requires exactly the 12 installer-package files:
  - `wd.exe`
  - `wd-agent.exe`
  - `wd-routerctl.exe`
  - `wd-core.exe`
  - `wd-ui.exe`
  - `VERSION.txt`
  - `SHA256SUMS.txt`
  - `Install-WeDecent.ps1`
  - `Uninstall-WeDecent.ps1`
  - `Test-WeDecentInstall.ps1`
  - `README.md`
  - `PACKAGE_SHA256SUMS.txt`;
- requires the single `version=` entry in `VERSION.txt` to match the signed manifest version;
- verifies `SHA256SUMS.txt` covers exactly the five binaries and matches their extracted bytes;
- verifies `PACKAGE_SHA256SUMS.txt` covers exactly the 11 package payload files and matches their extracted bytes; and
- requires an Authenticode policy callback to approve all five binaries and all three PowerShell scripts.

Only after every check succeeds is the consumer callback invoked. The temporary package directory is removed immediately after the consumer returns, whether the consumer succeeds or fails. Callers must not retain package paths after returning from the callback.

## Authenticode policy

`AuthenticodeVerifier` is intentionally a required injected policy boundary. A production verifier must fail closed unless the file satisfies the approved WeDecent publisher identity, certificate-chain validity, Authenticode signature validity, and timestamp policy.

The `updateinfo` package does not accept an optional or best-effort signature mode. A nil verifier is an error and the package consumer is never called. Raw verifier errors are not propagated through the package-verification error text.

This slice does not provision the production publisher policy or update-signing key. Those remain deployment concerns and must not be inferred from package contents.

## Remaining application boundary

A later installer-application slice must invoke the installer from inside the verified-package callback so verification and consumption stay adjacent. That later slice must also define:

- exact PowerShell invocation and elevation behavior;
- user-process / service preflight and restart semantics;
- installation failure recovery;
- post-install version validation; and
- anti-rollback sequence commit only after installation is known to have succeeded.

Package verification alone never advances update sequence state.
