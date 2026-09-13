import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import {
  consumeConnectionGrant,
  INTERNAL_GRANT_EXP_HEADER,
  INTERNAL_GRANT_JTI_HEADER,
  prepareDeviceRelayRequest,
  replayMetadataFromRequest,
} from "../src/grant-replay.js";
import { deviceIDFromPublicKey } from "../src/relay-auth.js";
import { authorizeStream, CONNECTION_GRANT_HEADER } from "../src/stream-auth.js";

const now = 1_800_000_000;
const userID = "0b7729e9-95bf-4591-80f4-3f0616e57751";
const clientDeviceID = "wd_aaaaaaaaaaaaaaaa";
const otherClientDeviceID = "wd_bbbbbbbbbbbbbbbb";
const grantKeys = generateKeyPairSync("ed25519");
const publicSPKIB64 = grantKeys.publicKey.export({ type: "spki", format: "der" }).toString("base64");
const publicJWK = grantKeys.publicKey.export({ format: "jwk" });
const kid = b64url(createHash("sha256").update(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: publicJWK.x })).digest());
const enc = new TextEncoder();
const signingContext = "wedecent-relay-ticket-v2\n";

async function issueAuthorizationTicket({ subjectOverride = "" } = {}) {
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const issuer = await deviceIDFromPublicKey(rawPublicKey);
  const claims = {
    v: 2,
    aud: "wedecent-relay",
    iss: issuer,
    sub: subjectOverride || issuer,
    role: "authorize",
    iat: now,
    exp: now + 90,
    jti: b64url(Uint8Array.from({ length: 16 }, (_, i) => i + 1)),
    pk: b64url(rawPublicKey),
  };
  const payload = b64url(enc.encode(JSON.stringify(claims)));
  const signature = await crypto.subtle.sign("Ed25519", keys.privateKey, enc.encode(signingContext + payload));
  return { token: `wdt2.${payload}.${b64url(new Uint8Array(signature))}`, claims };
}

async function issueClientTicket(targetDeviceID) {
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const issuer = await deviceIDFromPublicKey(rawPublicKey);
  const claims = {
    v: 2,
    aud: "wedecent-relay",
    iss: issuer,
    sub: targetDeviceID,
    role: "client",
    iat: now,
    exp: now + 90,
    jti: b64url(Uint8Array.from({ length: 16 }, (_, i) => i + 17)),
    pk: b64url(rawPublicKey),
  };
  const payload = b64url(enc.encode(JSON.stringify(claims)));
  const signature = await crypto.subtle.sign("Ed25519", keys.privateKey, enc.encode(signingContext + payload));
  return { token: `wdt2.${payload}.${b64url(new Uint8Array(signature))}`, claims };
}

function issueGrant(clientID, targetID, overrides = {}) {
  const header = { alg: "EdDSA", typ: "JWT", kid };
  const claims = {
    grant_id: "d90987bf-bae6-45da-ab21-c82d049617bd",
    organization_id: "7140858e-39db-4a54-a707-88d5e86b910c",
    client_device_id: clientID,
    target_device_id: targetID,
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

function directRequest(ticket, grant) {
  return new Request("https://relay.test/v1/direct-authorize/unused", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${ticket}`,
      [CONNECTION_GRANT_HEADER]: grant,
    },
  });
}

function websocketRequest(ticket, grant, targetDeviceID) {
  return new Request(`https://relay.test/v1/stream/${targetDeviceID}?role=client`, {
    headers: {
      Authorization: `Bearer ${ticket}`,
      [CONNECTION_GRANT_HEADER]: grant,
      Upgrade: "websocket",
    },
  });
}

function directReplayRequest(replay) {
  return new Request("https://wedecent.internal/authorize", {
    method: "POST",
    headers: {
      [INTERNAL_GRANT_JTI_HEADER]: replay.jti,
      [INTERNAL_GRANT_EXP_HEADER]: String(replay.exp),
    },
  });
}

async function consumeReplayRequest(storage, request) {
  const replay = replayMetadataFromRequest(request);
  assert.ok(replay, "trusted replay metadata should be present");
  return consumeConnectionGrant(storage, replay.jti, replay.exp, now * 1000);
}

const env = { WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64: publicSPKIB64 };

test("accepts a self-bound authorization ticket and matching connection grant", async () => {
  const relay = await issueAuthorizationTicket();
  const result = await authorizeStream(
    directRequest(relay.token, issueGrant(clientDeviceID, relay.claims.iss)),
    env,
    { deviceId: relay.claims.iss, role: "authorize", slot: null, clientDeviceID },
    now,
  );
  assert.equal(result.ok, true);
  assert.deepEqual(result.replay, { jti: "76b4c468-4e39-437c-a9c8-b758c92ab89b", exp: now + 90 });
});

test("rejects direct authorization when the grant names another TLS client", async () => {
  const relay = await issueAuthorizationTicket();
  const result = await authorizeStream(
    directRequest(relay.token, issueGrant(otherClientDeviceID, relay.claims.iss)),
    env,
    { deviceId: relay.claims.iss, role: "authorize", slot: null, clientDeviceID },
    now,
  );
  assert.equal(result.ok, false);
  assert.equal(result.status, 403);
});

test("rejects a non-self-bound authorization ticket", async () => {
  const relay = await issueAuthorizationTicket({ subjectOverride: "wd_4ksk5edkttwsxqx4" });
  const result = await authorizeStream(
    directRequest(relay.token, issueGrant(clientDeviceID, relay.claims.iss)),
    env,
    { deviceId: relay.claims.iss, role: "authorize", slot: null, clientDeviceID },
    now,
  );
  assert.equal(result.ok, false);
  assert.equal(result.status, 401);
});

test("one replay store enforces single use across direct and websocket admission paths", async () => {
  const target = await issueAuthorizationTicket();
  const client = await issueClientTicket(target.claims.iss);
  const grant = issueGrant(client.claims.iss, target.claims.iss);

  const websocketOuter = websocketRequest(client.token, grant, target.claims.iss);
  const websocketAuthorization = await authorizeStream(
    websocketOuter,
    env,
    { deviceId: target.claims.iss, role: "client", slot: null },
    now,
  );
  assert.equal(websocketAuthorization.ok, true);
  const websocketInner = prepareDeviceRelayRequest(
    websocketOuter,
    websocketAuthorization.replay,
    CONNECTION_GRANT_HEADER,
  );

  const directAuthorization = await authorizeStream(
    directRequest(target.token, grant),
    env,
    { deviceId: target.claims.iss, role: "authorize", slot: null, clientDeviceID: client.claims.iss },
    now,
  );
  assert.equal(directAuthorization.ok, true);
  const directInner = directReplayRequest(directAuthorization.replay);

  for (const [firstName, firstRequest, secondName, secondRequest] of [
    ["websocket", websocketInner, "direct", directInner],
    ["direct", directInner, "websocket", websocketInner],
  ]) {
    const storage = new FakeStorage();
    const first = await consumeReplayRequest(storage, firstRequest);
    const second = await consumeReplayRequest(storage, secondRequest);
    assert.equal(first.accepted, true, `${firstName} should consume the fresh grant`);
    assert.equal(second.accepted, false, `${secondName} should see the grant as already used`);
  }
});

class FakeStorage {
  constructor() {
    this.data = new Map();
  }

  async transaction(fn) {
    return fn({
      get: async (key) => this.data.get(key),
      put: async (key, value) => this.data.set(key, value),
    });
  }
}

function jsonPart(value) {
  return b64url(Buffer.from(JSON.stringify(value)));
}

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}
