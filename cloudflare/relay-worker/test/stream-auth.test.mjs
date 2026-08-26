import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { authorizeStream, CONNECTION_GRANT_HEADER } from "../src/stream-auth.js";
import { deviceIDFromPublicKey } from "../src/relay-auth.js";

const now = 1_800_000_000;
const targetDeviceID = "wd_4ksk5edkttwsxqx4";
const userID = "0b7729e9-95bf-4591-80f4-3f0616e57751";
const grantKeys = generateKeyPairSync("ed25519");
const publicSPKIB64 = grantKeys.publicKey.export({ type: "spki", format: "der" }).toString("base64");
const publicJWK = grantKeys.publicKey.export({ format: "jwk" });
const kid = b64url(createHash("sha256").update(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: publicJWK.x })).digest());
const enc = new TextEncoder();
const signingContext = "wedecent-relay-ticket-v2\n";

async function issueRelayTicket({ role = "client", slot = null } = {}) {
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const issuer = await deviceIDFromPublicKey(rawPublicKey);
  const claims = {
    v: 2,
    aud: "wedecent-relay",
    iss: issuer,
    sub: role === "agent" ? issuer : targetDeviceID,
    role,
    ...(role === "agent" ? { slot } : {}),
    iat: now,
    exp: now + 90,
    jti: b64url(Uint8Array.from({ length: 16 }, (_, i) => i + 1)),
    pk: b64url(rawPublicKey),
  };
  const payload = b64url(enc.encode(JSON.stringify(claims)));
  const signature = await crypto.subtle.sign("Ed25519", keys.privateKey, enc.encode(signingContext + payload));
  return { token: `wdt2.${payload}.${b64url(new Uint8Array(signature))}`, claims };
}

function issueGrant(clientDeviceID, overrides = {}) {
  const header = { alg: "EdDSA", typ: "JWT", kid };
  const claims = {
    grant_id: "d90987bf-bae6-45da-ab21-c82d049617bd",
    organization_id: "7140858e-39db-4a54-a707-88d5e86b910c",
    client_device_id: clientDeviceID,
    target_device_id: targetDeviceID,
    permission: "terminal.connect",
    iss: "wedecent-control-plane",
    aud: "wedecent-relay",
    sub: userID,
    jti: "76b4c468-4e39-437c-a9c8-b758c92ab89b",
    iat: now,
    exp: now + 90,
    ...overrides,
  };
  const input = `${jsonPart(header)}.${jsonPart(claims)}`;
  return `${input}.${b64url(sign(null, Buffer.from(input), grantKeys.privateKey))}`;
}

function request(ticket, grant = "") {
  const headers = new Headers({ Authorization: `Bearer ${ticket}` });
  if (grant) headers.set(CONNECTION_GRANT_HEADER, grant);
  return new Request(`https://relay.test/v1/stream/${targetDeviceID}?role=client`, { headers });
}

const env = { WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64: publicSPKIB64, RELAY_ACCESS_TOKEN: "legacy" };

test("accepts a client only when relay ticket and connection grant scopes match", async () => {
  const relay = await issueRelayTicket();
  const result = await authorizeStream(
    request(relay.token, issueGrant(relay.claims.iss)),
    env,
    { deviceId: targetDeviceID, role: "client", slot: null },
    now,
  );
  assert.equal(result.ok, true);
  assert.deepEqual(result.replay, { jti: "76b4c468-4e39-437c-a9c8-b758c92ab89b", exp: now + 90 });
});

test("rejects a client with no connection grant", async () => {
  const relay = await issueRelayTicket();
  const result = await authorizeStream(request(relay.token), env, { deviceId: targetDeviceID, role: "client", slot: null }, now);
  assert.equal(result.ok, false);
  assert.equal(result.status, 403);
});

test("rejects a connection grant for another client", async () => {
  const relay = await issueRelayTicket();
  const result = await authorizeStream(
    request(relay.token, issueGrant("wd_mw3am46w5weex4a4")),
    env,
    { deviceId: targetDeviceID, role: "client", slot: null },
    now,
  );
  assert.equal(result.ok, false);
  assert.equal(result.status, 403);
});

test("rejects legacy shared-token client bypass", async () => {
  const req = new Request(`https://relay.test/v1/stream/${targetDeviceID}?role=client`, {
    headers: { Authorization: "Bearer legacy" },
  });
  const result = await authorizeStream(req, env, { deviceId: targetDeviceID, role: "client", slot: null }, now);
  assert.equal(result.ok, false);
});

test("accepts an authenticated agent slot without a connection grant", async () => {
  const relay = await issueRelayTicket({ role: "agent", slot: 4 });
  const req = new Request(`https://relay.test/v1/stream/${relay.claims.iss}?role=agent&slot=4`, {
    headers: { Authorization: `Bearer ${relay.token}` },
  });
  const result = await authorizeStream(req, env, { deviceId: relay.claims.iss, role: "agent", slot: 4 }, now);
  assert.deepEqual(result, { ok: true });
});

function jsonPart(value) {
  return b64url(Buffer.from(JSON.stringify(value)));
}

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}
