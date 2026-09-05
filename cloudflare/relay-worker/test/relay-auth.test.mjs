import assert from "node:assert/strict";
import test from "node:test";

import { deviceIDFromPublicKey, verifyRelayTicket } from "../src/relay-auth.js";

const enc = new TextEncoder();
const signingContext = "wedecent-relay-ticket-v2\n";

function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

async function issueTicket({ target, role, slot, now }) {
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const issuer = await deviceIDFromPublicKey(publicKey);
  const claims = {
    v: 2,
    aud: "wedecent-relay",
    iss: issuer,
    sub: role === "agent" ? issuer : target,
    role,
    ...(role === "agent" ? { slot } : {}),
    iat: now,
    exp: now + 90,
    jti: b64url(Uint8Array.from({ length: 16 }, (_, i) => i)),
    pk: b64url(publicKey),
  };
  const payload = b64url(enc.encode(JSON.stringify(claims)));
  const signature = await crypto.subtle.sign("Ed25519", keys.privateKey, enc.encode(signingContext + payload));
  return { token: `wdt2.${payload}.${b64url(new Uint8Array(signature))}`, claims };
}


test("device ID derivation matches the Go identity format", async () => {
  const publicKey = Buffer.from("79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664", "hex");
  assert.equal(await deviceIDFromPublicKey(publicKey), "wd_mw3am46w5weex4a4");
});


test("verifies the Go relay-ticket test vector", async () => {
  const token = "wdt2.eyJ2IjoyLCJhdWQiOiJ3ZWRlY2VudC1yZWxheSIsImlzcyI6IndkX213M2FtNDZ3NXdlZXg0YTQiLCJzdWIiOiJ3ZF80a3NrNWVka3R0d3N4cXg0Iiwicm9sZSI6ImNsaWVudCIsImlhdCI6MTgwMDAwMDAwMCwiZXhwIjoxODAwMDAwMDkwLCJqdGkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R3IiwicGsiOiJlYlZXTG9fbVZQbEFlTEVTNkttTHA1QWZoVHJtbGI3WDRPT1JDNjBFbG1RIn0.DxjsYtag4atT2i07p591gAcmvjSd5IaXpVnEAGhRo1-uWY1CqynldMGlPczzyMWioTYLdZhzgMkqkpMfBihOCA";
  const got = await verifyRelayTicket(token, { deviceId: "wd_4ksk5edkttwsxqx4", role: "client", slot: null }, 1_800_000_000);
  assert.equal(got.iss, "wd_mw3am46w5weex4a4");
});

test("verifies a scoped client ticket", async () => {
  const now = 1_800_000_000;
  const target = "wd_4ksk5edkttwsxqx4";
  const { token, claims } = await issueTicket({ target, role: "client", slot: null, now });
  const got = await verifyRelayTicket(token, { deviceId: target, role: "client", slot: null }, now);
  assert.equal(got.iss, claims.iss);
  assert.equal(got.sub, target);
  assert.equal(got.role, "client");
});

test("agent ticket is bound to its own device and slot", async () => {
  const now = 1_800_000_000;
  const { token, claims } = await issueTicket({ target: "unused", role: "agent", slot: 4, now });
  await verifyRelayTicket(token, { deviceId: claims.iss, role: "agent", slot: 4 }, now);
  await assert.rejects(() => verifyRelayTicket(token, { deviceId: claims.iss, role: "agent", slot: 3 }, now));
});

test("rejects expired and tampered tickets", async () => {
  const now = 1_800_000_000;
  const target = "wd_4ksk5edkttwsxqx4";
  const { token } = await issueTicket({ target, role: "client", slot: null, now });
  await assert.rejects(() => verifyRelayTicket(token, { deviceId: target, role: "client", slot: null }, now + 300));
  const parts = token.split(".");
  parts[2] = (parts[2][0] === "A" ? "B" : "A") + parts[2].slice(1);
  await assert.rejects(() => verifyRelayTicket(parts.join("."), { deviceId: target, role: "client", slot: null }, now));
});
