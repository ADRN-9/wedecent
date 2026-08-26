import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const deviceIDPattern = /^wd_[a-z2-7]{16}$/;
const publicKeyPattern = /^[A-Za-z0-9_-]{43}$/;
const uuidPattern = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
const challengeTTLMS = 5 * 60 * 1000;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "no-store" },
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
  throw new Error("Supabase secret key is not configured");
}

function decodeBase64URL(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function encodeBase64URL(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function hex(value: Uint8Array): string {
  return Array.from(value, (b) => b.toString(16).padStart(2, "0")).join("");
}

function base32NoPad(value: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let buffer = 0;
  let out = "";
  for (const byte of value) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(buffer >>> bits) & 31];
    }
  }
  if (bits > 0) out += alphabet[(buffer << (5 - bits)) & 31];
  return out;
}

async function deviceIDFromPublicKey(publicKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey));
  return "wd_" + base32NoPad(digest.slice(0, 10)).toLowerCase();
}

function signingMessage(input: {
  challengeId: string;
  challenge: string;
  userId: string;
  deviceId: string;
  publicKey: string;
  kind: string;
  organizationId: string | null;
  expiresUnixMS: number;
}): Uint8Array {
  const org = input.organizationId ?? "-";
  return new TextEncoder().encode(
    `wedecent-enrollment-v1\n` +
      `challenge_id=${input.challengeId}\n` +
      `challenge=${input.challenge}\n` +
      `user_id=${input.userId}\n` +
      `device_id=${input.deviceId}\n` +
      `public_key=${input.publicKey}\n` +
      `kind=${input.kind}\n` +
      `organization_id=${org}\n` +
      `expires_unix_ms=${input.expiresUnixMS}\n`,
  );
}

function validateCommon(body: Record<string, unknown>) {
  const deviceId = String(body.device_id ?? "");
  const publicKey = String(body.public_key ?? "");
  const kind = String(body.kind ?? "");
  const name = String(body.name ?? "").trim();
  const organizationId = body.organization_id == null || body.organization_id === "" ? null : String(body.organization_id);

  if (!deviceIDPattern.test(deviceId)) throw new Error("invalid device_id");
  if (!publicKeyPattern.test(publicKey)) throw new Error("invalid public_key");
  if (!['client', 'agent', 'hybrid'].includes(kind)) throw new Error("invalid kind");
  if (name.length < 1 || name.length > 128) throw new Error("invalid name");
  if (organizationId !== null && !uuidPattern.test(organizationId)) throw new Error("invalid organization_id");

  const publicKeyBytes = decodeBase64URL(publicKey);
  if (publicKeyBytes.length !== 32) throw new Error("public_key must decode to 32 bytes");
  return { deviceId, publicKey, publicKeyBytes, kind, name, organizationId };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  try {
    const authorization = req.headers.get("Authorization");
    const token = authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (!token) return json({ error: "authentication required" }, 401);

    const url = Deno.env.get("SUPABASE_URL");
    if (!url) throw new Error("SUPABASE_URL is not configured");
    const admin = createClient(url, serviceKey(), {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    const { data: authData, error: authError } = await admin.auth.getUser(token);
    if (authError || !authData.user) return json({ error: "invalid user session" }, 401);
    const userId = authData.user.id;

    const body = await req.json() as Record<string, unknown>;
    const action = String(body.action ?? "");
    const common = validateCommon(body);
    const derived = await deviceIDFromPublicKey(common.publicKeyBytes);
    if (derived !== common.deviceId) return json({ error: "device_id does not match public_key" }, 400);

    if (common.organizationId !== null) {
      const { data: membership, error: membershipError } = await admin
        .from("organization_memberships")
        .select("role")
        .eq("organization_id", common.organizationId)
        .eq("user_id", userId)
        .maybeSingle();
      if (membershipError) throw membershipError;
      if (!membership || !['owner', 'admin'].includes(membership.role)) {
        return json({ error: "organization owner or admin role required" }, 403);
      }
    }

    const { data: existing, error: existingError } = await admin
      .from("devices")
      .select("device_id, public_key, kind, owner_user_id, revoked_at")
      .eq("device_id", common.deviceId)
      .maybeSingle();
    if (existingError) throw existingError;
    if (existing) {
      if (existing.revoked_at) return json({ error: "device is revoked" }, 409);
      if (existing.owner_user_id !== userId) return json({ error: "device belongs to another user" }, 409);
      if (existing.public_key !== common.publicKey || existing.kind !== common.kind) {
        return json({ error: "existing device identity does not match" }, 409);
      }
    }

    if (action === "challenge") {
      const challengeBytes = crypto.getRandomValues(new Uint8Array(32));
      const challenge = encodeBase64URL(challengeBytes);
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", challengeBytes));
      const expiresAt = new Date(Date.now() + challengeTTLMS);

      const { data: row, error } = await admin
        .from("device_enrollment_challenges")
        .insert({
          user_id: userId,
          device_id: common.deviceId,
          challenge_sha256: `\\x${hex(digest)}`,
          expires_at: expiresAt.toISOString(),
        })
        .select("id, expires_at")
        .single();
      if (error) throw error;

      return json({
        action: "challenge",
        challenge_id: row.id,
        challenge,
        user_id: userId,
        device_id: common.deviceId,
        public_key: common.publicKey,
        kind: common.kind,
        name: common.name,
        organization_id: common.organizationId,
        expires_unix_ms: Date.parse(row.expires_at),
      });
    }

    if (action === "complete") {
      const challengeId = String(body.challenge_id ?? "");
      const challenge = String(body.challenge ?? "");
      const signature = String(body.signature ?? "");
      if (!uuidPattern.test(challengeId)) return json({ error: "invalid challenge_id" }, 400);
      let challengeBytes: Uint8Array;
      let signatureBytes: Uint8Array;
      try {
        challengeBytes = decodeBase64URL(challenge);
        signatureBytes = decodeBase64URL(signature);
      } catch {
        return json({ error: "invalid enrollment proof encoding" }, 400);
      }
      if (challengeBytes.length !== 32 || signatureBytes.length !== 64) {
        return json({ error: "invalid enrollment proof length" }, 400);
      }

      const { data: challengeRow, error: challengeError } = await admin
        .from("device_enrollment_challenges")
        .select("id, user_id, device_id, expires_at, consumed_at")
        .eq("id", challengeId)
        .maybeSingle();
      if (challengeError) throw challengeError;
      if (!challengeRow || challengeRow.user_id !== userId || challengeRow.device_id !== common.deviceId) {
        return json({ error: "invalid enrollment challenge" }, 400);
      }
      if (challengeRow.consumed_at) return json({ error: "enrollment challenge already consumed" }, 409);
      const expiresUnixMS = Date.parse(challengeRow.expires_at);
      if (!Number.isFinite(expiresUnixMS) || expiresUnixMS <= Date.now()) {
        return json({ error: "enrollment challenge expired" }, 400);
      }

      const key = await crypto.subtle.importKey("raw", common.publicKeyBytes, { name: "Ed25519" }, false, ["verify"]);
      const message = signingMessage({
        challengeId,
        challenge,
        userId,
        deviceId: common.deviceId,
        publicKey: common.publicKey,
        kind: common.kind,
        organizationId: common.organizationId,
        expiresUnixMS,
      });
      const valid = await crypto.subtle.verify("Ed25519", key, signatureBytes, message);
      if (!valid) return json({ error: "invalid device signature" }, 403);

      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", challengeBytes));
      const { data: enrolled, error: enrollError } = await admin.rpc("complete_device_enrollment", {
        p_challenge_id: challengeId,
        p_user_id: userId,
        p_device_id: common.deviceId,
        p_public_key: common.publicKey,
        p_kind: common.kind,
        p_name: common.name,
        p_organization_id: common.organizationId,
        p_challenge_sha256_hex: hex(digest),
      });
      if (enrollError) {
        console.warn("device enrollment completion rejected", { code: enrollError.code, message: enrollError.message });
        return json({ error: "enrollment could not be completed" }, 409);
      }

      const device = Array.isArray(enrolled) ? enrolled[0] : enrolled;
      console.info("device enrolled", { user_id: userId, device_id: common.deviceId, organization_id: common.organizationId });
      return json({ action: "complete", device });
    }

    return json({ error: "action must be challenge or complete" }, 400);
  } catch (error) {
    console.error("device enrollment failed", error);
    return json({ error: "internal enrollment error" }, 500);
  }
});
