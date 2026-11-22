import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { authorizeStream, AGENT_ADMISSION_HEADER, CONNECTION_GRANT_HEADER } from "../src/stream-auth.js";
import { deviceIDFromPublicKey, devicePublicKeyFingerprint } from "../src/relay-auth.js";

const now = 1_800_000_000;
const targetDeviceID = "wd_4ksk5edkttwsxqx4";
const userID = "0b7729e9-95bf-4591-80f4-3f0616e57751";
const grantKeys = generateKeyPairSync("ed25519");
const publicSPKIB64 = grantKeys.publicKey.export({ type: "spki", format: "der" }).toString("base64");
const publicJWK = grantKeys.publicKey.export({ format: "jwk" });
const kid = b64url(createHash("sha256").update(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: publicJWK.x })).digest());
const admissionKeys = generateKeyPairSync("ed25519");
const admissionPublicSPKIB64 = admissionKeys.publicKey.export({ type: "spki", format: "der" }).toString("base64");
const admissionJWK = admissionKeys.publicKey.export({ format: "jwk" });
const admissionKID = b64url(createHash("sha256").update(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: admissionJWK.x })).digest());
const admissionKeyring = JSON.stringify({ [admissionKID]: admissionPublicSPKIB64 });
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
    sub: role === "client" ? targetDeviceID : issuer,
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

function issueAgentAdmission(deviceID, slot, publicKeyFingerprint, overrides = {}) {
  const header = { alg: "EdDSA", typ: "JWT", kid: admissionKID };
  const claims = {
    device_id: deviceID,
    public_key_fingerprint: publicKeyFingerprint,
    purpose: "relay.agent.connect",
    slot,
    iss: "wedecent-control-plane",
    aud: "wedecent-relay-agent",
    sub: deviceID,
    jti: "a90987bf-bae6-45da-ab21-c82d049617bd",
    iat: now,
    exp: now + 90,
    ...overrides,
  };
  const input = jsonPart(header) + "." + jsonPart(claims);
  return input + "." + b64url(sign(null, Buffer.from(input), admissionKeys.privateKey));
}

function request(ticket, grant = "", admission = "") {
  const headers = new Headers({ Authorization: `Bearer ${ticket}` });
  if (grant) headers.set(CONNECTION_GRANT_HEADER, grant);
  if (admission) headers.set(AGENT_ADMISSION_HEADER, admission);
  return new Request(`https://relay.test/v1/stream/${targetDeviceID}?role=client`, { headers });
}

const env = { WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64: publicSPKIB64, WEDECENT_AGENT_ADMISSION_PUBLIC_KEYS_JSON: admissionKeyring, RELAY_ACCESS_TOKEN: "legacy" };

test("accepts a client only when relay ticket and connection grant scopes match", async () => {
  const relay = await issueRelayTicket();
  const result = await authorizeStream(
    request(relay.token, issueGrant(relay.claims.iss)),
    env,
    { deviceId: targetDeviceID, role: "client", slot: null },
    now,
  );
  assert.equal(result.ok, true);
  assert.equal(result.deviceID, relay.claims.iss);
  assert.equal(result.targetDeviceID, targetDeviceID);
  assert.deepEqual(result.replay, { jti: "76b4c468-4e39-437c-a9c8-b758c92ab89b", exp: now + 90 });
});

test("direct authorization returns both grant-bound client and target identities", async () => {
  const relay = await issueRelayTicket({ role: "authorize" });
  const clientDeviceID = "wd_mw3am46w5weex4a4";
  const grant = issueGrant(clientDeviceID, { target_device_id: relay.claims.iss });
  const req = new Request("https://relay.test/v1/direct-authorize/" + relay.claims.iss, {
    headers: {
      Authorization: "Bearer " + relay.token,
      [CONNECTION_GRANT_HEADER]: grant,
    },
  });
  const result = await authorizeStream(
    req,
    env,
    {
      deviceId: relay.claims.iss,
      role: "authorize",
      clientDeviceID,
      slot: null,
    },
    now,
  );
  assert.equal(result.ok, true);
  assert.equal(result.deviceID, clientDeviceID);
  assert.equal(result.targetDeviceID, relay.claims.iss);
  assert.deepEqual(result.replay, { jti: "76b4c468-4e39-437c-a9c8-b758c92ab89b", exp: now + 90 });
});

test("rejects a client with no connection grant", async () => {
  const relay = await issueRelayTicket();
  const result = await authorizeStream(request(relay.token), env, { deviceId: targetDeviceID, role: "client", slot: null }, now);
  assert.equal(result.ok, false);
  assert.equal(result.status, 403);
});

test("rejects target identifier substitution before returning an authenticated quota identity", async () => {
  const relay = await issueRelayTicket();
  const alternateTarget = "wd_mw3am46w5weex4a4";
  const headers = new Headers({
    Authorization: "Bearer " + relay.token,
    [CONNECTION_GRANT_HEADER]: issueGrant(relay.claims.iss),
  });
  const req = new Request("https://relay.test/v1/stream/" + alternateTarget + "?role=client", { headers });
  const result = await authorizeStream(
    req,
    env,
    { deviceId: alternateTarget, role: "client", slot: null },
    now,
  );
  assert.equal(result.ok, false);
  assert.equal(result.deviceID, undefined);
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

test("legacy shared-token agents require control-plane admission", async () => {
  const req = new Request("https://relay.test/v1/stream/" + targetDeviceID + "?role=agent&slot=4", {
    headers: { Authorization: "Bearer legacy" },
  });
  const result = await authorizeStream(req, env, { deviceId: targetDeviceID, role: "agent", slot: 4 }, now);
  assert.equal(result.ok, false);
  assert.equal(result.status, 401);
});

test("legacy shared-token agents are rejected even with an admission bearer", async () => {
  const admission = issueAgentAdmission(targetDeviceID, 4, "SHA256:" + "A".repeat(64));
  const req = new Request("https://relay.test/v1/stream/" + targetDeviceID + "?role=agent&slot=4", {
    headers: {
      Authorization: "Bearer legacy",
      [AGENT_ADMISSION_HEADER]: admission,
    },
  });
  const result = await authorizeStream(req, env, { deviceId: targetDeviceID, role: "agent", slot: 4 }, now);
  assert.equal(result.ok, false);
  assert.equal(result.status, 401);
});

test("rejects legacy shared-token client bypass", async () => {
  const req = new Request(`https://relay.test/v1/stream/${targetDeviceID}?role=client`, {
    headers: { Authorization: "Bearer legacy" },
  });
  const result = await authorizeStream(req, env, { deviceId: targetDeviceID, role: "client", slot: null }, now);
  assert.equal(result.ok, false);
});

test("rejects a self-generated agent identity without control-plane admission", async () => {
  const relay = await issueRelayTicket({ role: "agent", slot: 4 });
  const req = new Request(`https://relay.test/v1/stream/${relay.claims.iss}?role=agent&slot=4`, {
    headers: { Authorization: `Bearer ${relay.token}` },
  });
  const result = await authorizeStream(req, env, { deviceId: relay.claims.iss, role: "agent", slot: 4 }, now);
  assert.equal(result.ok, false);
  assert.equal(result.status, 403);
});

test("accepts an enrolled agent only with a device- and slot-bound admission token", async () => {
  const relay = await issueRelayTicket({ role: "agent", slot: 4 });
  const fingerprint = await devicePublicKeyFingerprint(relay.claims.pk);
  const admission = issueAgentAdmission(relay.claims.iss, 4, fingerprint);
  const req = new Request(`https://relay.test/v1/stream/${relay.claims.iss}?role=agent&slot=4`, {
    headers: {
      Authorization: `Bearer ${relay.token}`,
      [AGENT_ADMISSION_HEADER]: admission,
    },
  });
  const result = await authorizeStream(req, env, { deviceId: relay.claims.iss, role: "agent", slot: 4 }, now);
  assert.deepEqual(result, {
    ok: true,
    deviceID: relay.claims.iss,
    targetDeviceID: relay.claims.iss,
    agentAdmissionReplay: { jti: "a90987bf-bae6-45da-ab21-c82d049617bd", exp: now + 90 },
    relayTicketReplay: { jti: relay.claims.jti, exp: relay.claims.exp },
  });
});

test("rejects an agent admission bound to a substituted public-key fingerprint", async () => {
  const relay = await issueRelayTicket({ role: "agent", slot: 4 });
  const wrongFingerprint = "SHA256:" + "B".repeat(64);
  const admission = issueAgentAdmission(relay.claims.iss, 4, wrongFingerprint);
  const req = new Request("https://relay.test/v1/stream/" + relay.claims.iss + "?role=agent&slot=4", {
    headers: {
      Authorization: "Bearer " + relay.token,
      [AGENT_ADMISSION_HEADER]: admission,
    },
  });
  const result = await authorizeStream(req, env, { deviceId: relay.claims.iss, role: "agent", slot: 4 }, now);
  assert.equal(result.ok, false);
  assert.equal(result.status, 403);
});

test("fails closed when the independent agent admission keyring is missing", async () => {
  const relay = await issueRelayTicket({ role: "agent", slot: 4 });
  const fingerprint = await devicePublicKeyFingerprint(relay.claims.pk);
  const admission = issueAgentAdmission(relay.claims.iss, 4, fingerprint);
  const req = new Request("https://relay.test/v1/stream/" + relay.claims.iss + "?role=agent&slot=4", {
    headers: {
      Authorization: "Bearer " + relay.token,
      [AGENT_ADMISSION_HEADER]: admission,
    },
  });
  const result = await authorizeStream(
    req,
    { ...env, WEDECENT_AGENT_ADMISSION_PUBLIC_KEYS_JSON: "" },
    { deviceId: relay.claims.iss, role: "agent", slot: 4 },
    now,
  );
  assert.equal(result.ok, false);
  assert.equal(result.status, 503);
});

test("rejects an agent admission token for another device or slot", async () => {
  const relay = await issueRelayTicket({ role: "agent", slot: 4 });
  const fingerprint = await devicePublicKeyFingerprint(relay.claims.pk);
  const wrongDevice = issueAgentAdmission(targetDeviceID, 4, fingerprint);
  const wrongSlot = issueAgentAdmission(relay.claims.iss, 5, fingerprint);
  for (const admission of [wrongDevice, wrongSlot]) {
    const req = new Request(`https://relay.test/v1/stream/${relay.claims.iss}?role=agent&slot=4`, {
      headers: {
        Authorization: `Bearer ${relay.token}`,
        [AGENT_ADMISSION_HEADER]: admission,
      },
    });
    const result = await authorizeStream(req, env, { deviceId: relay.claims.iss, role: "agent", slot: 4 }, now);
    assert.equal(result.ok, false);
    assert.equal(result.status, 403);
  }
});

function jsonPart(value) {
  return b64url(Buffer.from(JSON.stringify(value)));
}

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}
