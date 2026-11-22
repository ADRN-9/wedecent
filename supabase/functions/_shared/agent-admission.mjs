const DEVICE_ID = /^wd_[a-z2-7]{16}$/;
const FINGERPRINT = /^SHA256:[A-F0-9]{64}$/;
const PROOF_AUDIENCE = "wedecent-agent-admission";
const PROOF_PURPOSE = "relay.agent.admission.acquire";
const MAX_PROOF_LIFETIME_SECONDS = 30;
const CLOCK_SKEW_SECONDS = 30;
const REQUIRED_CLAIMS = new Set([
  "iss", "sub", "aud", "purpose", "device_id", "public_key_fingerprint",
  "slot", "iat", "exp", "jti",
]);

export async function deviceIDFromPublicKey(publicKeyBytes) {
  if (!(publicKeyBytes instanceof Uint8Array) || publicKeyBytes.length !== 32) {
    throw new Error("invalid enrolled device public key");
  }
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKeyBytes));
  return "wd_" + base32NoPadding(digest.subarray(0, 10));
}

export async function fingerprintDevicePublicKey(publicKeyBytes) {
  if (!(publicKeyBytes instanceof Uint8Array) || publicKeyBytes.length !== 32) {
    throw new Error("invalid enrolled device public key");
  }
  const key = await crypto.subtle.importKey(
    "raw",
    publicKeyBytes,
    { name: "Ed25519" },
    true,
    ["verify"],
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", key));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));
  return "SHA256:" + Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export async function verifyDeviceAdmissionProof(token, expected, publicKeyBytes, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (
    !expected ||
    typeof expected.deviceID !== "string" ||
    !DEVICE_ID.test(expected.deviceID) ||
    typeof expected.publicKeyFingerprint !== "string" ||
    !FINGERPRINT.test(expected.publicKeyFingerprint) ||
    !Number.isSafeInteger(expected.slot) ||
    expected.slot < 1 ||
    expected.slot > 32
  ) {
    throw new Error("invalid expected agent admission scope");
  }
  if (typeof token !== "string" || token.length < 32 || token.length > 4096) {
    throw new Error("invalid device proof length");
  }
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid device proof format");

  const header = decodeJSONObject(parts[0], "device proof header");
  const claims = decodeJSONObject(parts[1], "device proof claims");
  if (
    Object.keys(header).length !== 3 ||
    header.alg !== "EdDSA" ||
    header.typ !== "JWT" ||
    header.kid !== expected.publicKeyFingerprint
  ) {
    throw new Error("device proof key identification mismatch");
  }
  for (const field of REQUIRED_CLAIMS) {
    if (!Object.prototype.hasOwnProperty.call(claims, field)) {
      throw new Error("device proof is missing required claims");
    }
  }
  for (const field of Object.keys(claims)) {
    if (!REQUIRED_CLAIMS.has(field)) throw new Error("device proof contains unsupported claims");
  }
  if (
    claims.iss !== expected.deviceID ||
    claims.sub !== expected.deviceID ||
    claims.device_id !== expected.deviceID ||
    claims.aud !== PROOF_AUDIENCE ||
    claims.purpose !== PROOF_PURPOSE ||
    claims.public_key_fingerprint !== expected.publicKeyFingerprint ||
    claims.slot !== expected.slot
  ) {
    throw new Error("device proof scope mismatch");
  }
  if (
    !Number.isSafeInteger(claims.iat) ||
    claims.iat <= 0 ||
    !Number.isSafeInteger(claims.exp) ||
    claims.exp <= claims.iat ||
    claims.exp - claims.iat > MAX_PROOF_LIFETIME_SECONDS ||
    claims.iat > nowSeconds + CLOCK_SKEW_SECONDS ||
    claims.exp <= nowSeconds
  ) {
    throw new Error("device proof is expired or has an invalid lifetime");
  }
  const nonce = decodeBase64URL(claims.jti);
  if (nonce.length !== 16 || encodeBase64URL(nonce) !== claims.jti) {
    throw new Error("invalid device proof nonce");
  }
  if (!(publicKeyBytes instanceof Uint8Array) || publicKeyBytes.length !== 32) {
    throw new Error("invalid enrolled device public key");
  }

  const signature = decodeBase64URL(parts[2]);
  if (signature.length !== 64) throw new Error("invalid device proof signature");
  const key = await crypto.subtle.importKey(
    "raw",
    publicKeyBytes,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const signed = new TextEncoder().encode(parts[0] + "." + parts[1]);
  if (!(await crypto.subtle.verify("Ed25519", key, signature, signed))) {
    throw new Error("invalid device proof signature");
  }
  return claims;
}

function decodeJSONObject(value, name) {
  const bytes = decodeBase64URL(value);
  if (bytes.length === 0 || bytes.length > 2048) throw new Error("invalid " + name);
  try {
    const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("not an object");
    }
    return parsed;
  } catch {
    throw new Error("invalid " + name);
  }
}

function encodeBase64URL(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replaceAll("+", "-").replaceAll("/", "_");
}

function decodeBase64URL(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length % 4 === 1 ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw new Error("invalid base64url value");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("invalid base64url value");
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function base32NoPadding(bytes) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    if (bits > 24) value &= (1 << bits) - 1;
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
