# wedecent.com namespace

Recommended initial layout:

```text
wedecent.com             Product site
app.wedecent.com         Future web console
auth.wedecent.com        Future OIDC/auth service
api.wedecent.com         Future control API
relay.wedecent.com       Global relay entry point
docs.wedecent.com        Documentation
download.wedecent.com    Signed client/agent releases
```

## MVP DNS

Create `A` and, if available, `AAAA` records for:

```text
relay.wedecent.com
```

pointing to the relay host. `wd-relay` currently speaks a dedicated TLS protocol on TCP/443 rather than HTTP, so any CDN/reverse proxy in front of it must support transparent Layer-4 TCP pass-through for that hostname. Otherwise point DNS directly to the relay host.

Install a publicly trusted certificate whose SAN includes `relay.wedecent.com` and run:

```bash
wd-relay \
  --listen :443 \
  --cert /path/to/fullchain.pem \
  --key /path/to/privkey.pem
```

The outer relay certificate protects the client/agent-to-relay hop. The inner device-pinned TLS channel separately protects the terminal from the relay itself.

## Future regional layout

```text
ca-east.relay.wedecent.com
us-east.relay.wedecent.com
us-west.relay.wedecent.com
eu-west.relay.wedecent.com
ap-southeast.relay.wedecent.com
```

A future control plane can return a ranked relay list while retaining `relay.wedecent.com` as the simple default.
