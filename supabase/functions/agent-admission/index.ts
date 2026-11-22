import { createClient } from "npm:@supabase/supabase-js@2";
import { calculateJwkThumbprint, exportJWK, importPKCS8, importSPKI, SignJWT } from "npm:jose@6";
import {
  deviceIDFromPublicKey,
  fingerprintDevicePublicKey,
  verifyDeviceAdmissionProof,
} from "../_shared/agent-admission.mjs";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Cache-Control": "no-store",
};

const deviceIDPattern = /^wd_[a-z2-7]{16}$/;
const issuer = "wedecent-control-plane";
const audience = "wedecent-relay-agent";
const purpose = "relay.agent.connect";
const maximumBodyBytes = 4096;
const capabilityLifetimeSeconds = 90;

class AdmissionError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "AdmissionError";
    this.status = status;
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function serviceKey(): string {
  const legacy = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (legacy) return legacy;
  const raw = Deno.env.get("SUPABASE_SECRET_KEYS");
  if (raw) {
    const keys = JSON.parse(raw) as Record<string, string>;
    if (keys.default) return keys.default;
  }
  throw new Error("Supabase service key is not configured");
}

function signingKeyPEM(): string {
  const der = Deno.env.get("WEDECENT_AGENT_ADMISSION_PKCS8_B64")?.trim();
  if (!der || !/^[A-Za-z0-9+/=]+$/.test(der)) {
    throw new Error("WEDECENT_AGENT_ADMISSION_PKCS8_B64 is not configured");
  }
  const lines = der.match(/.{1,64}/g) ?? [];
  return "-----BEGIN PRIVATE KEY-----\n" + lines.join("\n") + "\n-----END PRIVATE KEY-----";
}

function admissionPublicKeyPEM(): string {
  const der = Deno.env.get("WEDECENT_AGENT_ADMISSION_PUBLIC_SPKI_B64")?.trim();
  if (!der || !/^[A-Za-z0-9+/=]+$/.test(der)) {
    throw new Error("WEDECENT_AGENT_ADMISSION_PUBLIC_SPKI_B64 is not configured");
  }
  const lines = der.match(/.{1,64}/g) ?? [];
  return "-----BEGIN PUBLIC KEY-----\\n" + lines.join("\\n") + "\\n-----END PUBLIC KEY-----";
}

function connectionGrantPublicKeyPEM(): string {
  const der = Deno.env.get("WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64")?.trim();
  if (!der || !/^[A-Za-z0-9+/=]+$/.test(der)) {
    throw new Error("WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64 is required to enforce key separation");
  }
  const lines = der.match(/.{1,64}/g) ?? [];
  return "-----BEGIN PUBLIC KEY-----\n" + lines.join("\n") + "\n-----END PUBLIC KEY-----";
}

let signerPromise: Promise<{ key: CryptoKey; kid: string }> | null = null;

async function signer(): Promise<{ key: CryptoKey; kid: string }> {
  if (!signerPromise) {
    signerPromise = (async () => {
      const key = await importPKCS8(signingKeyPEM(), "EdDSA", { extractable: false });
      const publicKey = await importSPKI(admissionPublicKeyPEM(), "EdDSA", { extractable: true });
      const publicJWK = await exportJWK(publicKey);
      const kid = await calculateJwkThumbprint(publicJWK, "sha256");
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const signature = await crypto.subtle.sign({ name: "Ed25519" }, key, challenge);
      const matchesPublicKey = await crypto.subtle.verify({ name: "Ed25519" }, publicKey, signature, challenge);
      if (!matchesPublicKey) {
        throw new Error("agent admission private key does not match its configured public key");
      }
      const terminalKey = await importSPKI(connectionGrantPublicKeyPEM(), "EdDSA", { extractable: true });
      const terminalJWK = await exportJWK(terminalKey);
      const terminalKID = await calculateJwkThumbprint(terminalJWK, "sha256");
      if (kid === terminalKID) {
        throw new Error("agent admission signing key must be independent from terminal connection grants");
      }
      return { key, kid };
    })();
  }
  try {
    return await signerPromise;
  } catch (error) {
    signerPromise = null;
    throw error;
  }
}

function parseDeviceID(value: unknown): string {
  if (typeof value !== "string" || !deviceIDPattern.test(value)) {
    throw new AdmissionError("invalid device_id", 400);
  }
  return value;
}

function parseSlot(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > 32) {
    throw new AdmissionError("invalid agent slot", 400);
  }
  return value;
}

function decodeBase64URL(value: string): Uint8Array {
  if (!value || value.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new AdmissionError("invalid enrolled device key", 403);
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new AdmissionError("invalid enrolled device key", 403);
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function readBody(request: Request): Promise<Record<string, unknown>> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null) {
    if (!/^[0-9]+$/.test(declared)) throw new AdmissionError("invalid request body", 400);
    const length = Number(declared);
    if (!Number.isSafeInteger(length)) throw new AdmissionError("invalid request body", 400);
    if (length > maximumBodyBytes) throw new AdmissionError("request body too large", 413);
  }
  const reader = request.body?.getReader();
  if (!reader) throw new AdmissionError("invalid request body", 400);
  const chunks: Uint8Array[] = [];
  let total = 0;
  let count = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      count++;
      total += value.byteLength;
      if (count > 32 || total > maximumBodyBytes) {
        void reader.cancel().catch(() => {});
        throw new AdmissionError("request body too large", 413);
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof AdmissionError) throw error;
    throw new AdmissionError("invalid request body", 400);
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // A failed release does not change the fail-closed request result.
    }
  }
  if (total === 0 || (declared !== null && Number(declared) !== total)) {
    throw new AdmissionError("invalid request body", 400);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new AdmissionError("invalid request body", 400);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new AdmissionError("invalid request body", 400);
  }
  return parsed as Record<string, unknown>;
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);

  let admin: ReturnType<typeof createClient> | null = null;
  let auditDeviceID: string | null = null;
  let auditSlot: number | null = null;
  let auditProofJTI: string | null = null;
  let auditAlreadyRecorded = false;

  try {
    const url = Deno.env.get("SUPABASE_URL");
    if (!url) throw new Error("SUPABASE_URL is not configured");
    const adminClient = createClient(url, serviceKey(), {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    admin = adminClient;

    const { data: rateAllowed, error: rateLimitError } = await adminClient.rpc(
      "consume_agent_admission_endpoint_request",
    );
    if (rateLimitError) throw new Error("agent admission endpoint rate limiter unavailable");
    if (rateAllowed !== true) {
      auditAlreadyRecorded = true;
      throw new AdmissionError("agent admission endpoint rate limit exceeded", 429);
    }

    const body = await readBody(request);
    if (
      Object.keys(body).length !== 3 ||
      !Object.prototype.hasOwnProperty.call(body, "device_id") ||
      !Object.prototype.hasOwnProperty.call(body, "slot") ||
      !Object.prototype.hasOwnProperty.call(body, "proof")
    ) {
      throw new AdmissionError("invalid request fields", 400);
    }
    const deviceID = parseDeviceID(body.device_id);
    auditDeviceID = deviceID;
    const slot = parseSlot(body.slot);
    auditSlot = slot;
    if (typeof body.proof !== "string" || body.proof.length < 32 || body.proof.length > 4096) {
      throw new AdmissionError("invalid device proof", 400);
    }

    const { data: device, error: deviceError } = await adminClient
      .from("devices")
      .select("device_id, public_key, kind, revoked_at")
      .eq("device_id", deviceID)
      .maybeSingle();
    if (deviceError) throw new Error("enrolled device lookup failed");
    if (!device || !["agent", "hybrid"].includes(device.kind)) {
      throw new AdmissionError("agent device is not enrolled or is not an agent", 403);
    }
    if (device.revoked_at !== null) {
      throw new AdmissionError("agent device is revoked", 403);
    }

    const publicKeyBytes = decodeBase64URL(String(device.public_key ?? ""));
    if (publicKeyBytes.length !== 32 || await deviceIDFromPublicKey(publicKeyBytes) !== deviceID) {
      throw new AdmissionError("enrolled device identity is invalid", 403);
    }
    let fingerprint: string;
    try {
      fingerprint = await fingerprintDevicePublicKey(publicKeyBytes);
    } catch {
      throw new AdmissionError("enrolled device identity is invalid", 403);
    }
    let proofClaims: { jti: string; exp: number };
    try {
      proofClaims = await verifyDeviceAdmissionProof(
        body.proof,
        { deviceID, publicKeyFingerprint: fingerprint, slot },
        publicKeyBytes,
      );
    } catch {
      throw new AdmissionError("device proof rejected", 403);
    }
    auditProofJTI = proofClaims.jti;

    const signing = await signer();
    const { data: consumed, error: consumeError } = await adminClient.rpc("consume_agent_admission_proof", {
      p_device_id: deviceID,
      p_public_key: String(device.public_key),
      p_jti: proofClaims.jti,
      p_expires_at: new Date(proofClaims.exp * 1000).toISOString(),
    });
    if (consumeError?.code === "42501") {
      throw new AdmissionError("agent device is not enrolled or is revoked", 403);
    }
    if (consumeError) throw new Error("agent proof replay service unavailable");
    if (consumed === "replay") {
      auditAlreadyRecorded = true;
      throw new AdmissionError("device proof has already been used", 409);
    }
    if (consumed === "rate_limited") {
      auditAlreadyRecorded = true;
      throw new AdmissionError("agent admission issuance rate limit exceeded", 429);
    }
    if (consumed !== "accepted") throw new Error("agent proof replay service returned an invalid result");

    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAt = issuedAt + capabilityLifetimeSeconds;
    const jti = crypto.randomUUID();
    const admission = await new SignJWT({
      device_id: deviceID,
      public_key_fingerprint: fingerprint,
      purpose,
      slot,
    })
      .setProtectedHeader({ alg: "EdDSA", typ: "JWT", kid: signing.kid })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject(deviceID)
      .setJti(jti)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAt)
      .sign(signing.key);

    const { error: auditError } = await adminClient.rpc("record_agent_admission_audit", {
      p_device_id: deviceID,
      p_event_type: "issued",
      p_slot: slot,
      p_proof_jti: proofClaims.jti,
      p_admission_jti: jti,
      p_reason: "issued",
    });
    if (auditError) throw new Error("agent admission issuance audit persistence unavailable");

    return json({
      agent_admission: admission,
      claims: {
        iss: issuer,
        aud: audience,
        sub: deviceID,
        jti,
        device_id: deviceID,
        public_key_fingerprint: fingerprint,
        purpose,
        slot,
        iat: issuedAt,
        exp: expiresAt,
        kid: signing.kid,
      },
    });
  } catch (error) {
    if (error instanceof AdmissionError) {
      if (admin && !auditAlreadyRecorded) {
        const reason = error.message === "device proof rejected"
          ? "invalid_proof"
          : error.message === "agent device is revoked" ||
              error.message === "agent device is not enrolled or is revoked"
            ? "device_revoked"
            : "request_rejected";
        const { error: auditError } = await admin.rpc("record_agent_admission_audit", {
          p_device_id: auditDeviceID,
          p_event_type: "rejected",
          p_slot: auditSlot,
          p_proof_jti: auditProofJTI,
          p_admission_jti: null,
          p_reason: reason,
        });
        if (auditError) {
          console.error("agent-admission rejection audit unavailable", { code: auditError.code });
          return json({ error: "agent admission audit unavailable" }, 503);
        }
      }
      return json({ error: error.message }, error.status);
    }
    console.error("agent-admission unavailable", error);
    return json({ error: "agent admission service unavailable" }, 503);
  }
});
