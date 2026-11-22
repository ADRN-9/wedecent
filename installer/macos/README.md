# macOS LaunchAgent

WeDecent uses a per-user LaunchAgent on macOS so the exposed remote shell runs as the logged-in account rather than root. Do not install this as root.

Installed paths are under the current user's home directory:

- binary: `~/Library/Application Support/WeDecent/bin/wd-agent`
- config: `~/Library/Application Support/WeDecent/agent.json`
- state/identity: `~/Library/Application Support/WeDecent/agent`
- logs: `~/Library/Application Support/WeDecent/logs`
- LaunchAgent: `~/Library/LaunchAgents/com.wedecent.agent.plist`

Install from a trusted checkout or package payload:

```sh
sh installer/macos/install-launch-agent.sh /absolute/path/to/wd-agent /absolute/path/to/agent.json
```

The installer rejects symlinked binary/config inputs, copies them with user-private modes, renders an absolute-path plist, validates it with `plutil`, and loads it into `gui/$UID` when a graphical login domain is available. Otherwise it will load at the next graphical login.

The normal strict `wd-agent serve --config` parser still validates the installed JSON. The LaunchAgent also fixes the state path separately, so configuration cannot redirect the service identity/state location.

## Device-authenticated relay admission

When enabling `web_relay`, also set `supabase_url` and
`supabase_publishable_key` in the strict agent JSON configuration:

```json
{
  "web_relay": "https://relay.wedecent.com",
  "supabase_url": "https://YOUR_PROJECT.supabase.co",
  "supabase_publishable_key": "sb_publishable_..."
}
```

The publishable key is public application configuration. The background service uses
the enrolled device's Ed25519 key to sign a short-lived proof and never receives a
user access token or refresh token. Missing admission configuration is a startup
error; there is no bearer-only agent fallback. See
`docs/AGENT_RELAY_ADMISSION.md` for independent signing-key provisioning and
rotation requirements.

Uninstall with:

```sh
sh installer/macos/uninstall-launch-agent.sh
```

Uninstall preserves config, state/identity, and logs to avoid accidental trust/identity destruction. Delete those files manually only when permanent removal is intended.
