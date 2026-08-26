const DEVICE_ID = /^wd_[a-z2-7]{16}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ISSUER = "wedecent-control-plane";
const AUDIENCE = "wedecent-relay";
const PERMISSION = "terminal.connect";
const MAX_TOKEN_LENGTH = 8192;
const MAX_LIFETIME_SECONDS = 120;
const CLOCK_SKEW_SECONDS = 30;

let cachedPublicKey = null;
let cachedSPKI = "";
let cachedKID = "";

export async function verifyConnectionGrant(
  token,
  expected,
  publicSPKIB64,
  nowSeconds = Math.floor(Date.now() / 1000),
) {
  if (typeof token !== "string" || token.length < 32 || token.length > MAX_TOKEN_LENGTH) {
    throw new Error("invalid connection grant length");
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("invalid connection grant format");
  }

  const header = decodeJSONObject(parts[0], "connection grant header");
  const claims = decodeJSONObject(parts[1], "connection grant claims");

  if (header.alg !== "EdDSA" || header.typ !== "JWT" || typeof header.kid !== "string" || header.kid.length === 0) {
    throw new Error("unsupported connection grant header");
  }
  validateClaims(claims);

  if (claims.iss !== ISSUER || claims.aud !== AUDIENCE) {
    throw new Error("unsupported connection grant issuer or audience");
  }
  if (claims.permission !== PERMISSION || expected.permission !== PERMISSION) {
    throw new Error("connection grant permission mismatch");
  }
  if (claims.client_device_id !== expected.clientDeviceID || claims.target_device_id !== expected.targetDeviceID) {
    throw new Error("connection grant device scope mismatch");
  }
  if (!Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) || claims.exp <= claims.iat) {
    throw new Error("invalid connection grant lifetime");
  }
  if (claims.exp - claims.iat > MAX_LIFETIME_SECONDS) {
    throw new Error("connection grant lifetime is too long");
  }
  if (claims.iat > nowSeconds + CLOCK_SKEW_SECONDS || claims.exp < nowSeconds - CLOCK_SKEW_SECONDS) {
    throw new Error("connection grant is not currently valid");
  }

  const signature = decodeBase64URL(parts[2]);
  if (signature.length !== 64) {
    throw new Error("invalid connection grant signature length");
  }
  const { key, kid } = await connectionGrantPublicKey(publicSPKIB64);
  if (header.kid !== kid) {
    throw new Error("connection grant signing key mismatch");
  }
  const signed = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  if (!(await crypto.subtle.verify("Ed25519", key, signature, signed))) {
    throw new Error("invalid connection grant signature");
  }
  return claims;
}

function validateClaims(claims) {
  if (claims === null || typeof claims !== "object" || Array.isArray(claims)) {
    throw new Error("invalid connection grant claims");
  }
  for (const field of ["grant_id", "iss", "aud", "sub", "jti", "client_device_id", "target_device_id", "permission", "iat", "exp"]) {
    if (!Object.prototype.hasOwnProperty.call(claims, field)) {
      throw new Error("connection grant is missing required claims");
    }
  }
  for (const field of ["grant_id", "iss", "aud", "sub", "jti", "client_device_id", "target_device_id", "permission"]) {
    if (typeof claims[field] !== "string" || claims[field].length === 0) {
      throw new Error("invalid connection grant claim type");
    }
  }
  if (!UUID.test(claims.grant_id) || !UUID.test(claims.jti) || !UUID.test(claims.sub)) {
    throw new Error("invalid connection grant identifier");
  }
  if (claims.organization_id !== null && claims.organization_id !== undefined && !UUID.test(String(claims.organization_id))) {
    throw new Error("invalid connection grant organization ID");
  }
  if (!DEVICE_ID.test(claims.client_device_id) || !DEVICE_ID.test(claims.target_device_id)) {
    throw new Error("invalid connection grant device ID");
  }
}

async function connectionGrantPublicKey(publicSPKIB64) {
  const normalized = typeof publicSPKIB64 === "string" ? publicSPKIB64.trim() : "";
  if (!normalized || normalized.length > 1024 || !/^[A-Za-z0-9+/=]+$/.test(normalized)) {
    throw new Error("connection grant public key is not configured");
  }
  if (cachedPublicKey && cachedSPKI === normalized) {
    return { key: cachedPublicKey, kid: cachedKID };
  }
  const spki = decodeBase64(normalized);
  const key = await crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, true, ["verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error("invalid connection grant public key");
  }
  const canonical = new TextEncoder().encode(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: jwk.x }));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", canonical));
  cachedPublicKey = key;
  cachedSPKI = normalized;
  cachedKID = encodeBase64URL(digest);
  return { key, kid: cachedKID };
}

function decodeJSONObject(value, name) {
  const bytes = decodeBase64URL(value);
  if (bytes.length === 0 || bytes.length > 4096) {
    throw new Error(`invalid ${name}`);
  }
  try {
    const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("not an object");
    }
    return parsed;
  } catch {
    throw new Error(`invalid ${name}`);
  }
}

function decodeBase64URL(value) {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("invalid base64url value");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  return decodeBase64(padded);
}

function decodeBase64(value) {
  let binary;
  try {
    binary = atob(value);
  } catch {
    throw new Error("invalid base64 value");
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function encodeBase64URL(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
