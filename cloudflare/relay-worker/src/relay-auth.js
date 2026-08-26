const DEVICE_ID = /^wd_[a-z2-7]{16}$/;
const TOKEN_PREFIX = "wdt2";
const AUDIENCE = "wedecent-relay";
const SIGNING_CONTEXT = "wedecent-relay-ticket-v2\n";
const MAX_TICKET_LENGTH = 2048;
const MAX_LIFETIME_SECONDS = 120;
const CLOCK_SKEW_SECONDS = 30;
const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const REQUIRED_KEYS = new Set(["v", "aud", "iss", "sub", "role", "iat", "exp", "jti", "pk"]);
const ALLOWED_KEYS = new Set([...REQUIRED_KEYS, "slot"]);

export async function verifyRelayTicket(token, expected, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (typeof token !== "string" || token.length < 32 || token.length > MAX_TICKET_LENGTH) {
    throw new Error("invalid relay ticket length");
  }
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX) {
    throw new Error("invalid relay ticket format");
  }

  const payloadBytes = decodeBase64URL(parts[1]);
  if (payloadBytes.length === 0 || payloadBytes.length > 1024) {
    throw new Error("invalid relay ticket payload length");
  }
  let claims;
  try {
    claims = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes));
  } catch {
    throw new Error("invalid relay ticket payload");
  }
  validateClaimsShape(claims);

  if (claims.v !== 2 || claims.aud !== AUDIENCE) {
    throw new Error("unsupported relay ticket");
  }
  if (!DEVICE_ID.test(claims.iss) || !DEVICE_ID.test(claims.sub)) {
    throw new Error("invalid relay ticket device ID");
  }
  if (claims.sub !== expected.deviceId || claims.role !== expected.role) {
    throw new Error("relay ticket scope mismatch");
  }
  if (claims.role === "agent") {
    if (claims.iss !== claims.sub || !Number.isInteger(claims.slot) || claims.slot !== expected.slot) {
      throw new Error("invalid agent relay ticket scope");
    }
  } else if (claims.role === "client") {
    if (claims.slot !== undefined || expected.slot !== null) {
      throw new Error("invalid client relay ticket scope");
    }
  } else {
    throw new Error("invalid relay ticket role");
  }

  if (!Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) || claims.exp <= claims.iat) {
    throw new Error("invalid relay ticket lifetime");
  }
  if (claims.exp - claims.iat > MAX_LIFETIME_SECONDS) {
    throw new Error("relay ticket lifetime is too long");
  }
  if (claims.iat > nowSeconds + CLOCK_SKEW_SECONDS || claims.exp < nowSeconds - CLOCK_SKEW_SECONDS) {
    throw new Error("relay ticket is not currently valid");
  }

  const tokenID = decodeBase64URL(claims.jti);
  if (tokenID.length !== 16) {
    throw new Error("invalid relay ticket ID");
  }
  const publicKey = decodeBase64URL(claims.pk);
  if (publicKey.length !== 32) {
    throw new Error("invalid relay ticket public key");
  }
  if ((await deviceIDFromPublicKey(publicKey)) !== claims.iss) {
    throw new Error("relay ticket issuer does not match public key");
  }

  const signature = decodeBase64URL(parts[2]);
  if (signature.length !== 64) {
    throw new Error("invalid relay ticket signature length");
  }
  const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
  const signed = new TextEncoder().encode(SIGNING_CONTEXT + parts[1]);
  if (!(await crypto.subtle.verify("Ed25519", key, signature, signed))) {
    throw new Error("invalid relay ticket signature");
  }
  return claims;
}

export async function deviceIDFromPublicKey(publicKey) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey));
  return "wd_" + base32NoPadding(digest.subarray(0, 10));
}

function validateClaimsShape(claims) {
  if (claims === null || typeof claims !== "object" || Array.isArray(claims)) {
    throw new Error("invalid relay ticket claims");
  }
  for (const key of REQUIRED_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(claims, key)) {
      throw new Error("relay ticket is missing required claims");
    }
  }
  for (const key of Object.keys(claims)) {
    if (!ALLOWED_KEYS.has(key)) {
      throw new Error("relay ticket contains unsupported claims");
    }
  }
  for (const key of ["aud", "iss", "sub", "role", "jti", "pk"]) {
    if (typeof claims[key] !== "string" || claims[key].length === 0) {
      throw new Error("invalid relay ticket claim type");
    }
  }
  if (!Number.isSafeInteger(claims.v)) {
    throw new Error("invalid relay ticket version");
  }
}

function decodeBase64URL(value) {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("invalid base64url value");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("invalid base64url value");
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function base32NoPadding(bytes) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    if (bits > 24) {
      value &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}
