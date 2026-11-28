# Windows updater privileged acceptance dependency

## Status

The repository contains transaction-aware updater code and hosted CI coverage, but hosted Windows runners do not establish acceptance of the privileged service-install/update path on a persistent Windows VM.

This gate remains open until an operator records a real-hardware/VM run covering:

- Upgrade an existing WeDecent service while preserving all five installed binaries' previous SHA-256 digests.
- Interrupt the installer during each replacement boundary and terminate the updater process.
- Reboot or restart the persistent VM and run the supported recovery path.
- Verify either the complete target installation or restoration of all five original binaries, with each digest checked against the pre-transaction snapshot.
- Verify transaction journal, updater sequence, installed-version authority, service state, and retained backups are mutually consistent.
- Exercise corrupted/missing backup, malformed or mismatched journal, replayed transaction ID, stale sequence, forged package, and downgrade attempts; each must fail closed without deleting the only recoverable original.
- Record VM image/build, Windows version, privilege context, test script revision, exact repository SHA, timestamps, logs, and final binary digests.

## Operational wiring boundary

`cmd/wd-agent/main.go` dispatches the `update` command to `runUpdateCommand`, and `cmd/wd-agent/update_windows.go` calls `updateinfo.ApplyInstalledWindowsStable`. The updater therefore has a source-level shipped service entrypoint. `DiscoveryClient.ApplyStable` invokes the `InstallerRecovery` capability before another update discovery, and `PowerShellInstallerExecutor` provides the journal-backed Windows recovery adapter. This source wiring is not privileged runtime acceptance: no persistent VM execution has yet demonstrated the elevated state store, Authenticode verification, SCM replacement, process isolation, reboot, and recovery sequence end to end. A privileged updater host still requires authenticated protected state, the configured Authenticode verifier, install/state paths, service identity, and elevated execution context.

## Accountable ownership

**Accountable repository owner:** ADRN-9, as the repository maintainer currently authoring the updater branch. ADRN-9 must name the operator responsible for provisioning and retaining the persistent privileged Windows VM and attach the resulting evidence to PR #209 before the gate can be accepted.

**Accountable infrastructure owner:** ADRN-9 is the accountable repository/infrastructure owner for provisioning the privileged Windows VM and retaining its evidence. An individual VM operator has not yet been designated in the inspected repository records; naming that operator and recording the persistent VM identifier remain open acceptance actions.

**Execution status:** No persistent privileged Windows VM identity, provisioned machine, named VM operator, or real privileged restart/reboot acceptance evidence was found in the repository evidence inspected for this task. The hosted Windows Actions runner is ephemeral CI and is not a substitute.

## Evidence classification

- Hosted Windows Actions: useful automated build, parser, and test evidence; not persistent VM acceptance.
- Go updater tests and process-termination tests: software-level transaction/journal evidence; not actual Windows binary replacement or service reboot proof.
- Required acceptance: operator-executed privileged Windows VM test with retained logs and before/after SHA-256 manifests.

No production signing, release publication, or deployment is authorized by this document.
