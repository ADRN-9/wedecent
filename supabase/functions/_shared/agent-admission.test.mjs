import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import {
  deviceIDFromPublicKey,
  fingerprintDevicePublicKey,
  verifyDeviceAdmissionProof,
} from "./agent-admission.mjs";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const rawPublicKey = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
const deviceID = await deviceIDFromPublicKey(rawPublicKey);
const fingerprint = await fingerprintDevicePublicKey(rawPublicKey);
const now = 1_800_000_000;

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}

function issueProof(overrides = {}, headerOverrides = {}) {
  const header = { alg: "EdDSA", typ: "JWT", kid: fingerprint, ...headerOverrides };
  const claims = {
    iss: deviceID,
    sub: deviceID,
    aud: "wedecent-agent-admission",
    purpose: "relay.agent.admission.acquire",
    device_id: deviceID,
    public_key_fingerprint: fingerprint,
    slot: 4,
    iat: now,
    exp: now + 30,
    jti: b64url(Buffer.alloc(16, 7)),
    ...overrides,
  };
  const input = b64url(JSON.stringify(header)) + "." + b64url(JSON.stringify(claims));
  return input + "." + b64url(sign(null, Buffer.from(input), privateKey));
}

const expected = { deviceID, publicKeyFingerprint: fingerprint, slot: 4 };

test("derives the enrolled device ID and SPKI fingerprint", async () => {
  assert.match(deviceID, /^wd_[a-z2-7]{16}$/);
  assert.equal(fingerprint, "SHA256:" + createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex").toUpperCase());
});

test("accepts a valid device-authenticated proof", async () => {
  const claims = await verifyDeviceAdmissionProof(issueProof(), expected, rawPublicKey, now);
  assert.equal(claims.device_id, deviceID);
  assert.equal(claims.slot, 4);
});

test("rejects identity substitution, fingerprint substitution and slot substitution", async () => {
  await assert.rejects(() => verifyDeviceAdmissionProof(issueProof({ device_id: "wd_4ksk5edkttwsxqx4" }), expected, rawPublicKey, now));
  await assert.rejects(() => verifyDeviceAdmissionProof(issueProof({ public_key_fingerprint: "SHA256:" + "A".repeat(64) }), expected, rawPublicKey, now));
  await assert.rejects(() => verifyDeviceAdmissionProof(issueProof({ slot: 5 }), expected, rawPublicKey, now));
});

test("rejects expired, overlong and future proofs", async () => {
  await assert.rejects(() => verifyDeviceAdmissionProof(issueProof({ exp: now }), expected, rawPublicKey, now));
  await assert.rejects(() => verifyDeviceAdmissionProof(issueProof({ exp: now + 31 }), expected, rawPublicKey, now));
  await assert.rejects(() => verifyDeviceAdmissionProof(issueProof({ iat: now + 31, exp: now + 60 }), expected, rawPublicKey, now));
});

test("rejects signature tampering and unknown signing keys", async () => {
  const token = issueProof();
  const parts = token.split(".");
  parts[2] = (parts[2][0] === "A" ? "B" : "A") + parts[2].slice(1);
  await assert.rejects(() => verifyDeviceAdmissionProof(parts.join("."), expected, rawPublicKey, now));
  await assert.rejects(() => verifyDeviceAdmissionProof(issueProof({}, { kid: "unknown" }), expected, rawPublicKey, now));
});

test("rejects malformed proof encodings", async () => {
  await assert.rejects(() => verifyDeviceAdmissionProof("not-a-jwt", expected, rawPublicKey, now));
  await assert.rejects(() => verifyDeviceAdmissionProof(issueProof(), expected, rawPublicKey.subarray(1), now));
});
