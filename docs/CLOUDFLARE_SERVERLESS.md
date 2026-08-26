# WeDecent Serverless Relay on Cloudflare

This is the preferred Internet transport for the MVP.

```text
wd client  --WSS-->  Cloudflare Worker / Durable Object  <--WSS--  wd-agent
     \___________________ inner TLS 1.3 E2EE ___________________/
```

The Cloudflare relay sees encrypted TLS records and routing metadata only. The agent does not open an inbound Internet port.

## 1. Deploy the Worker

The Durable Object namespace and custom domain are declared in `cloudflare/relay-worker/wrangler.jsonc`.

```bash
cd cloudflare/relay-worker
npm install
npm test
npx wrangler deploy
```

Verify:

```bash
curl https://relay.wedecent.com/healthz
```

Expected for relay-auth-v2:

```json
{"service":"wedecent-relay","status":"ok","version":5}
```

## 2. Relay authentication v2

Normal v0.3 `wd` and `wd-agent` processes do **not** need a shared relay token. Every WebSocket upgrade carries a fresh 90-second `wdt2` proof-of-possession ticket signed by the endpoint's existing Ed25519 identity key.

The Worker verifies the ticket with Web Crypto and binds it to the requested device, relay role, and agent slot. See [`RELAY_AUTH_V2.md`](RELAY_AUTH_V2.md).

The inner pinned TLS session remains the terminal authorization boundary. A client relay ticket proves possession of a client identity key; it does not by itself authorize that identity to open a terminal on a target agent.

## 3. Legacy/admin relay token

During migration, Worker v5 still accepts the existing `RELAY_ACCESS_TOKEN` from old stream binaries. The same secret also protects the operator-only `/v1/status/<device-id>` diagnostic endpoint.

Deploy Worker v5 first. Keep the secret configured in Cloudflare while older binaries exist, but do not distribute or configure it on upgraded v0.3 clients or agents.

If needed, configure it with Wrangler or the Cloudflare Dashboard as an encrypted Worker secret. Never commit or paste it into logs, screenshots, source files, or chat.

After all stream endpoints use relay-auth-v2, remove legacy stream-token acceptance and rotate the remaining admin/status credential.

## 4. Start the remote agent

No relay secret is required:

```bash
./bin/wd-agent serve \
  --listen '' \
  --web-relay https://relay.wedecent.com \
  --relay-slots 4 \
  --shell /bin/bash
```

`--listen ''` means the agent exposes no WeDecent inbound TCP listener.

## 5. Pair from the client

```bash
./bin/wd init --name system-1
./bin/wd pair \
  --web-relay https://relay.wedecent.com \
  --device-id wd_xxxxxxxxxxxxxxxx \
  --fingerprint 'SHA256:...'
```

Enter the one-time pairing secret from the agent when prompted.

## 6. Connect

The paired device stores its `wsrelay://` locator:

```bash
./bin/wd connect wd_xxxxxxxxxxxxxxxx
```

No shared relay token is required for the stream.

## Security notes

- `wdt2` tickets are short-lived and signed with endpoint Ed25519 identity keys.
- Agent tickets are self-bound to the agent device ID and a specific parked slot.
- Client tickets are target-bound, but account-level permission is still enforced by the target agent's paired-client trust store, not by Cloudflare.
- The Worker cannot decrypt terminal contents.
- Production still needs per-IP/identity/device rate limiting and server-issued account/RBAC grants.
- Rotate any legacy `RELAY_ACCESS_TOKEN` that has ever been distributed to endpoints once migration is complete.

## Relay status diagnostic

The status endpoint remains operator-only during this phase:

```bash
curl -sS \
  -H "Authorization: Bearer $WEDECENT_RELAY_TOKEN" \
  https://relay.wedecent.com/v1/status/wd_exampledeviceid
```

It returns counts for total/open/free agent slots and clients. The endpoint never returns terminal data or secrets.
