# Windows UI autostart

## Decision

Windows UI autostart is an explicit per-user opt-in owned by `wd-ui.exe` itself. The elevated machine installer does not enable, disable, or otherwise choose autostart for an interactive user.

The supported commands are:

```powershell
& 'C:\Program Files\WeDecent\wd-ui.exe' autostart enable
& 'C:\Program Files\WeDecent\wd-ui.exe' autostart status
& 'C:\Program Files\WeDecent\wd-ui.exe' autostart disable
```

`status` prints one of:

```text
enabled
disabled
stale
```

`stale` means the dedicated WeDecent current-user startup entry exists but does not exactly match the resolved `wd-ui.exe` image that is running the command. `enable` replaces that dedicated entry with the exact current image; `disable` removes only that entry and is idempotent.

## Windows mechanism

On Windows, `wd-ui` stores one `REG_SZ` value named `WeDecent` under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

The value contains only the fully resolved, absolute `wd-ui.exe` path, surrounded by quotes. It contains no shell command, arguments, account credentials, route information, environment expansion, or path lookup.

Before enabling autostart, `wd-ui` resolves its current executable path through filesystem indirection and requires the resolved target to be an existing regular file. Paths containing NUL, carriage return, line feed, or a quote are rejected instead of being written as a startup command.

Only `wd-ui.exe` is registered. `wd-core.exe` is never added to the Run key. At logon the UI starts in the interactive user's context and then uses the existing bounded same-user Local Core bootstrap path if the protected Local Core endpoint is absent. This preserves the same user token, per-SID named-pipe boundary, Core state directory ownership, and existing recovery rules.

## Security boundary

The Run key is convenience state owned by the current user, not an authorization mechanism. A user who can modify their own HKCU startup configuration can already change programs that run at their own logon. Autostart therefore grants no router, agent, trust-store, account, route, terminal, or machine-service privilege.

The feature deliberately does not:

- create or modify an HKLM Run entry;
- create a Scheduled Task;
- register `wd-core.exe` as a service or startup program;
- run Core or UI under the `WeDecentSvc` agent account;
- request elevation;
- search `PATH`;
- invoke `cmd.exe`, PowerShell, a shell verb, or another command interpreter;
- place credentials, tokens, grants, or private data in the startup command;
- let the elevated installer guess which interactive user's HKCU hive should own startup state.

Raw registry/path/OS errors are CLI-local failures and are not part of the Local Core protocol. The autostart subcommand does not instantiate the Core client, launch Core, or open the GUI.

## Installation, upgrade, and uninstall

The Windows installer continues to install `wd-ui.exe` and `wd-core.exe` into the protected Program Files directory but does not automatically opt any user into autostart. This avoids incorrectly assigning per-user startup state when installation is performed by another administrator through UAC or another elevated session.

An enabled Run entry points at the installed `wd-ui.exe`. Normal in-place upgrades keep the same path, so the entry remains valid when the image is replaced successfully. Existing installer behavior still fails closed if a running UI/Core image prevents replacement; close the user-side processes and retry the upgrade.

Before uninstalling, an opted-in user should run:

```powershell
& 'C:\Program Files\WeDecent\wd-ui.exe' autostart disable
```

The elevated uninstaller does not enumerate or mutate arbitrary users' HKCU hives. If the binary is removed while the entry remains, Windows may keep a harmless stale startup value pointing to the removed image. That user can remove the value from their own startup settings/registry. Reinstalling to the same path followed by `autostart enable` also repairs a stale WeDecent entry.

## Compatibility

Non-Windows builds reject the `autostart` command as unsupported. The no-argument `wd-ui` GUI startup path and the existing `version` command are otherwise unchanged.
