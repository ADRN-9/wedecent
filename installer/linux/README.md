# Linux systemd service

The packaged service runs `wd-agent` as a dedicated unprivileged `wedecent` system account. It deliberately uses fixed machine-wide paths:

- binary: `/usr/local/libexec/wedecent/wd-agent`
- config: `/etc/wedecent/agent.json`
- state/identity: `/var/lib/wedecent/agent`
- unit: `/etc/systemd/system/wedecent-agent.service`

Create the JSON configuration first. The normal strict `wd-agent serve --config` parser applies: the file must be a regular non-symlink file, is size-bounded, rejects unknown keys and trailing JSON, and on Unix rejects group/world-writable configuration.

Install from a trusted checkout or package payload:

```sh
sudo sh installer/linux/install-service.sh /absolute/path/to/wd-agent /absolute/path/to/agent.json
```

The installer creates the `wedecent` account if necessary, copies the binary/config with fixed ownership and modes, creates the private state directory, installs the hardened unit, and enables/starts it.

The service intentionally has no capabilities and cannot write outside `/var/lib/wedecent`. Configure an unprivileged shell path in `agent.json`; do not point it at a privileged wrapper.

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

Uninstall the service files with:

```sh
sudo sh installer/linux/uninstall-service.sh
```

Uninstall preserves `/etc/wedecent` and `/var/lib/wedecent` so identity/trust/configuration are not accidentally destroyed. Remove those directories manually only when permanent identity and state deletion is intended.
