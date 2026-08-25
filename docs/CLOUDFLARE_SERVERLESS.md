# WeDecent Serverless Relay on Cloudflare

This is the preferred Internet transport for the MVP.

```text
wd client  --WSS-->  Cloudflare Worker / Durable Object  <--WSS--  wd-agent
     \___________________ inner TLS 1.3 E2EE ___________________/
```

The Cloudflare relay sees encrypted TLS records and routing metadata only. The agent does not open an inbound Internet port.

## 1. Deploy the Worker once

The Durable Object namespace is declared in `cloudflare/relay-worker/wrangler.jsonc`. Cloudflare provisions the SQLite-backed namespace during deployment.

```bash
cd cloudflare/relay-worker
npm install
npx wrangler login
npx wrangler deploy
```

## 2. Set the relay access secret in the dashboard

Generate a high-entropy token locally:

```bash
openssl rand -base64 32
```

In Cloudflare Dashboard:

1. **Workers & Pages** -> **wedecent-relay**.
2. **Settings** -> **Variables and Secrets**.
3. Add encrypted secret `RELAY_ACCESS_TOKEN`.
4. Paste the generated value and save/deploy.

Do not commit or paste this token into chat, logs, screenshots, or source files.

## 3. Add the custom domain in the dashboard

In Cloudflare Dashboard:

1. **Workers & Pages** -> **wedecent-relay**.
2. **Domains** (or **Settings -> Domains & Routes**).
3. **Add** -> **Custom Domain**.
4. Enter `relay.wedecent.com`.
5. Save.

Cloudflare creates the DNS record and certificate automatically.

Verify:

```bash
curl https://relay.wedecent.com/healthz
```

Expected:

```json
{"service":"wedecent-relay","status":"ok","version":2}
```

## 4. Start the remote agent

Set the same secret in the agent's environment. Prefer an OS secret/service environment file instead of shell history for production.

```bash
export WEDECENT_RELAY_TOKEN='YOUR_PRIVATE_TOKEN'
./bin/wd-agent serve \
  --listen '' \
  --web-relay https://relay.wedecent.com \
  --relay-slots 4 \
  --shell /bin/bash
```

`--listen ''` means the agent exposes no WeDecent inbound TCP listener.

## 5. Pair from the client

```bash
export WEDECENT_RELAY_TOKEN='YOUR_PRIVATE_TOKEN'
./bin/wd init --name system-1
./bin/wd pair \
  --web-relay https://relay.wedecent.com \
  --device-id wd_xxxxxxxxxxxxxxxx \
  --fingerprint 'SHA256:...'
```

Enter the one-time pairing secret from the agent when prompted.

## 6. Connect

The paired device stores its `wsrelay://` locator, so subsequent connections only need:

```bash
export WEDECENT_RELAY_TOKEN='YOUR_PRIVATE_TOKEN'
./bin/wd connect wd_xxxxxxxxxxxxxxxx
```

## Security notes

- The shared relay access token is an MVP anti-abuse gate, not the long-term authorization design.
- End-to-end TLS between `wd` and `wd-agent` still authenticates the paired device/client independently of Cloudflare.
- The Worker cannot decrypt terminal contents.
- Device/user authorization will move to short-lived Supabase-issued credentials in a later control-plane phase.
- Rotate `RELAY_ACCESS_TOKEN` if it is exposed.


## Relay status diagnostic

The v0.2.2 Worker exposes an authenticated per-device status endpoint:

```bash
curl -sS \
  -H "Authorization: Bearer $WEDECENT_RELAY_TOKEN" \
  https://relay.wedecent.com/v1/status/wd_exampledeviceid
```

It returns counts for total/open/free agent slots and clients. The endpoint never returns terminal data or secrets.

The v0.2.2 Go WebSocket transport also sends RFC 6455 ping control frames every 30 seconds to keep restrictive NAT/proxy paths alive while agent slots are parked.
