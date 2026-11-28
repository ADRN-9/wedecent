# Windows update application and sequence commit

This document defines the mutation boundary after a stable update manifest, installer download, and exact package/Authenticode verification have already succeeded.

## Ordering invariant

`StateStore.ApplyVerifiedInstaller` owns one update transaction:

1. validate the signed manifest;
2. acquire the process-local mutex and a protected OS-level update lock;
3. re-read anti-rollback state and reject any sequence that is not newer;
4. enter `WithVerifiedInstallerPackage`, which re-hashes and re-verifies the staged package immediately before use;
5. invoke the installer executor while the verified package directory still exists;
6. wait for a known installer success/failure outcome; and
7. advance `update-state.json` only after installer success.

The lock file lives beside protected update state and is itself required to be a stable regular non-symlink file. Unix uses an exclusive `flock`; Windows uses an exclusive `LockFileEx`. Contending update processes wait until the owner releases the lock, then re-read sequence state before they can reach the installer. Cancellation while waiting aborts before mutation.

A failed installer never advances the anti-rollback sequence. If installation succeeds but the protected state write fails, the caller receives `ErrSequenceCommit`. That error means the installed update may already be active and the installer must not be blindly replayed as if no mutation occurred.

## Cancellation

Caller cancellation is honored until the installer mutation begins. Once `InstallerExecutor.Execute` starts, it receives `context.WithoutCancel` so a UI shutdown or request cancellation cannot abandon the privileged installer halfway through its own rollback transaction. The call waits for a known installer result before deciding whether sequence state may advance.

This deliberately favors a known filesystem/service outcome over prompt cancellation once mutation starts.

## PowerShell execution policy

`PowerShellInstallerExecutor` is the Windows execution policy boundary.

It requires an absolute regular non-symlink PowerShell executable path. It does not search `PATH`, use `cmd.exe`, build a shell command string, or request elevation implicitly. On Windows, `Execute`, `Recover`, and `FinalizeCommitted` also require the current process token to be elevated; a non-elevated caller is rejected before PowerShell starts. The caller is responsible for starting the update application in an already-elevated trusted process when elevation is required.

For each verified package it runs, in order:

1. `Test-WeDecentInstall.ps1` as a preflight;
2. `Install-WeDecent.ps1` with `-BundlePath` set to the callback-scoped verified package directory; and
3. `Test-WeDecentInstall.ps1` again as post-install validation.

All scripts were already required to pass the injected Authenticode policy before the executor can be reached. PowerShell is invoked directly with `-NoProfile`, `-NonInteractive`, and `-ExecutionPolicy AllSigned`.

The preflight prevents this update path from silently becoming a fresh installation: it requires the existing installation, service, metadata, binary commands, account, and state permissions to validate before `Install-WeDecent.ps1` is allowed to run.

`Install-WeDecent.ps1` remains the mutation/recovery engine. It already stages replacement binaries through `.new`/`.bak`, verifies installed hashes, restarts and validates the agent service, and restores previous binaries/service state when an in-transaction upgrade step fails. The postflight adds a final full installed-state check before anti-rollback state is committed.

Raw privileged-process errors and PowerShell output are not surfaced through `ApplyVerifiedInstaller`; callers receive stable error classes instead.

## User-process handoff

The installer continues to fail closed if the installed `wd-ui.exe` or `wd-core.exe` is still running. It never kills interactive user processes.

Therefore this primitive is not yet the UI handoff itself. A later UI/updater integration must close or transfer ownership away from those user processes before invoking application. It must not weaken the installer preflight to make in-process self-replacement appear to work.

## C337 runtime integration status

The repository still has no shipped product callsite for `DiscoveryClient.ApplyStable` or `PowerShellInstallerExecutor` in the inspected `wd-agent`, `wd-core`, CLI, or desktop entrypoints. The normal Windows agent service is installed under a dedicated standard account; it cannot satisfy the executor's elevated-token requirement. No authenticated privileged broker/service command or explicit elevated desktop handoff is implemented.

C337 adds tests that drive the updater API through the executor using a real child-process fixture. Those tests prove process invocation, argument binding, ordering, and failure propagation, but do not execute real PowerShell, elevate a process, or perform a service/binary update. This library path must not be represented as an operational shipped update feature until a product entrypoint and supported privilege handoff are implemented and exercised.

Do not solve this by elevating the general-purpose agent service or granting its standard account broad Program Files/SCM write access. The next integration must use an explicit UAC-consented helper or a dedicated narrowly scoped privileged broker with authenticated caller identity, transaction/package binding, anti-replay, protected staging, and audit.

## Remaining deployment work

This slice does not provision the production update public-key pin or production Authenticode publisher policy. Those remain explicit deployment tasks. It also does not mutate staging or production systems as part of CI.
