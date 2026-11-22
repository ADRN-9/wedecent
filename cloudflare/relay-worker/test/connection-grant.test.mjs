import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { verifyAgentAdmission, verifyConnectionGrant } from "../src/connection-grant.js";

const clientDeviceID = "wd_44qgdpulq5tcdo5e";
const targetDeviceID = "wd_surqdx3ktyrkje55";
const userID = "0b7729e9-95bf-4591-80f4-3f0616e57751";
const grantID = "d90987bf-bae6-45da-ab21-c82d049617bd";
const jti = "76b4c468-4e39-437c-a9c8-b758c92ab89b";
const organizationID = "7140858e-39db-4a54-a707-88d5e86b910c";
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const publicSPKIB64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
const publicJWK = publicKey.export({ format: "jwk" });
const kid = b64url(createHash("sha256").update(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: publicJWK.x })).digest());
const admissionKeys = generateKeyPairSync("ed25519");
const admissionPublicSPKIB64 = admissionKeys.publicKey.export({ type: "spki", format: "der" }).toString("base64");
const admissionJWK = admissionKeys.publicKey.export({ format: "jwk" });
const admissionKID = b64url(createHash("sha256").update(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: admissionJWK.x })).digest());
const admissionKeyring = JSON.stringify({ [admissionKID]: admissionPublicSPKIB64 });
const admissionFingerprint = "SHA256:" + "A".repeat(64);

function issueGrant(overrides = {}, headerOverrides = {}) {
  const now = 1_787_779_000;
  const header = { alg: "EdDSA", typ: "JWT", kid, ...headerOverrides };
  const claims = {
    grant_id: grantID,
    organization_id: organizationID,
    client_device_id: clientDeviceID,
    target_device_id: targetDeviceID,
    permission: "terminal.connect",
    iss: "wedecent-control-plane",
    aud: "wedecent-relay",
    sub: userID,
    jti,
    iat: now,
    exp: now + 90,
    ...overrides,
  };
  const signingInput = `${jsonPart(header)}.${jsonPart(claims)}`;
  return `${signingInput}.${b64url(sign(null, Buffer.from(signingInput), privateKey))}`;
}

async function verify(token, now = 1_787_779_010, expected = {}) {
  return verifyConnectionGrant(token, {
    clientDeviceID,
    targetDeviceID,
    permission: "terminal.connect",
    ...expected,
  }, publicSPKIB64, now);
}

test("accepts a valid scoped connection grant", async () => {
  const claims = await verify(issueGrant());
  assert.equal(claims.client_device_id, clientDeviceID);
  assert.equal(claims.target_device_id, targetDeviceID);
});

test("rejects a tampered signature", async () => {
  const token = issueGrant();
  const parts = token.split(".");
  parts[2] = `${parts[2][0] === "A" ? "B" : "A"}${parts[2].slice(1)}`;
  await assert.rejects(() => verify(parts.join(".")), /signature/);
});

test("rejects expired grants", async () => {
  await assert.rejects(() => verify(issueGrant(), 1_787_779_200), /currently valid/);
});

test("rejects the wrong permission", async () => {
  await assert.rejects(() => verify(issueGrant({ permission: "terminal.read" })), /permission/);
});

test("rejects a mismatched target device", async () => {
  await assert.rejects(() => verify(issueGrant({ target_device_id: "wd_4ksk5edkttwsxqx4" })), /device scope/);
});

test("rejects a mismatched client device", async () => {
  await assert.rejects(() => verify(issueGrant({ client_device_id: "wd_4ksk5edkttwsxqx4" })), /device scope/);
});

test("rejects a mismatched signing key id", async () => {
  await assert.rejects(() => verify(issueGrant({}, { kid: "wrong" })), /signing key mismatch/);
});

function issueAgentAdmission(overrides = {}, headerOverrides = {}) {
  const now = 1_787_779_000;
  const header = { alg: "EdDSA", typ: "JWT", kid: admissionKID, ...headerOverrides };
  const claims = {
    device_id: targetDeviceID,
    public_key_fingerprint: admissionFingerprint,
    purpose: "relay.agent.connect",
    slot: 4,
    iss: "wedecent-control-plane",
    aud: "wedecent-relay-agent",
    sub: targetDeviceID,
    jti: "d90987bf-bae6-45da-ab21-c82d049617bd",
    iat: now,
    exp: now + 90,
    ...overrides,
  };
  const signingInput = jsonPart(header) + "." + jsonPart(claims);
  return signingInput + "." + b64url(sign(null, Buffer.from(signingInput), admissionKeys.privateKey));
}

test("accepts a control-plane signed admission bound to an enrolled device and slot", async () => {
  const token = issueAgentAdmission();
  const claims = await verifyAgentAdmission(
    token,
    { deviceID: targetDeviceID, publicKeyFingerprint: admissionFingerprint, slot: 4 },
    admissionKeyring,
    1_787_779_010,
    publicSPKIB64,
  );
  assert.equal(claims.device_id, targetDeviceID);
  assert.equal(claims.public_key_fingerprint, admissionFingerprint);
  assert.equal(claims.purpose, "relay.agent.connect");
  assert.equal(claims.slot, 4);
});

test("rejects agent admission for another device, slot, audience, or purpose", async () => {
  const token = issueAgentAdmission();
  await assert.rejects(() => verifyAgentAdmission(token, { deviceID: clientDeviceID, publicKeyFingerprint: admissionFingerprint, slot: 4 }, admissionKeyring, 1_787_779_010, publicSPKIB64));
  await assert.rejects(() => verifyAgentAdmission(token, { deviceID: targetDeviceID, publicKeyFingerprint: admissionFingerprint, slot: 5 }, admissionKeyring, 1_787_779_010, publicSPKIB64));
  await assert.rejects(() => verifyAgentAdmission(issueAgentAdmission({ aud: "wedecent-relay" }), { deviceID: targetDeviceID, publicKeyFingerprint: admissionFingerprint, slot: 4 }, admissionKeyring, 1_787_779_010, publicSPKIB64));
  await assert.rejects(() => verifyAgentAdmission(issueAgentAdmission({ purpose: "terminal.connect" }), { deviceID: targetDeviceID, publicKeyFingerprint: admissionFingerprint, slot: 4 }, admissionKeyring, 1_787_779_010, publicSPKIB64));
});

test("rejects expired and overlong agent admission capabilities", async () => {
  await assert.rejects(() => verifyAgentAdmission(issueAgentAdmission(), { deviceID: targetDeviceID, publicKeyFingerprint: admissionFingerprint, slot: 4 }, admissionKeyring, 1_787_779_200, publicSPKIB64));
  await assert.rejects(() => verifyAgentAdmission(issueAgentAdmission({ exp: 1_787_779_010 }), { deviceID: targetDeviceID, publicKeyFingerprint: admissionFingerprint, slot: 4 }, admissionKeyring, 1_787_779_010, publicSPKIB64));
  await assert.rejects(() => verifyAgentAdmission(issueAgentAdmission({ exp: 1_787_779_200 }), { deviceID: targetDeviceID, publicKeyFingerprint: admissionFingerprint, slot: 4 }, admissionKeyring, 1_787_779_010, publicSPKIB64));
});

test("one agent admission cannot authorize thousands of arbitrary device identities", async () => {
  const token = issueAgentAdmission();
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  for (let index = 0; index < 4_500; index++) {
    let value = index;
    let suffix = "";
    for (let digit = 0; digit < 16; digit++) {
      suffix = alphabet[value % 32] + suffix;
      value = Math.floor(value / 32);
    }
    const candidate = "wd_" + suffix;
    if (candidate === targetDeviceID) continue;
    await assert.rejects(() => verifyAgentAdmission(
      token,
      { deviceID: candidate, publicKeyFingerprint: admissionFingerprint, slot: 4 },
      admissionKeyring,
      1_787_779_010,
      publicSPKIB64,
    ));
  }
});

test("rejects agent admission signed by an unknown key", async () => {
  await assert.rejects(() => verifyAgentAdmission(issueAgentAdmission({}, { kid: "wrong" }), { deviceID: targetDeviceID, publicKeyFingerprint: admissionFingerprint, slot: 4 }, admissionKeyring, 1_787_779_010, publicSPKIB64));
});

test("rejects an agent admission without its independent keyring", async () => {
  await assert.rejects(() => verifyAgentAdmission(
    issueAgentAdmission(),
    { deviceID: targetDeviceID, publicKeyFingerprint: admissionFingerprint, slot: 4 },
    "",
    1_787_779_010,
  ), /keyring/);
});

test("rejects a fingerprint substitution", async () => {
  await assert.rejects(() => verifyAgentAdmission(
    issueAgentAdmission(),
    { deviceID: targetDeviceID, publicKeyFingerprint: "SHA256:" + "B".repeat(64), slot: 4 },
    admissionKeyring,
    1_787_779_010,
  ), /scope/);
});

test("rejects reuse of the terminal connection-grant signing key", async () => {
  const terminalKeyring = JSON.stringify({ [kid]: publicSPKIB64 });
  await assert.rejects(() => verifyAgentAdmission(
    issueAgentAdmission({}, { kid }),
    { deviceID: targetDeviceID, publicKeyFingerprint: admissionFingerprint, slot: 4 },
    terminalKeyring,
    1_787_779_010,
    publicSPKIB64,
  ), /independent/);
});

function jsonPart(value) {
  return b64url(Buffer.from(JSON.stringify(value)));
}

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}
