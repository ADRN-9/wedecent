import { createClient } from "npm:@supabase/supabase-js@2";
import { calculateJwkThumbprint, exportJWK, importPKCS8, SignJWT } from "npm:jose@6";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const deviceIDPattern = /^wd_[a-z2-7]{16}$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const issuer = "wedecent-control-plane";
const audience = "wedecent-relay-agent";
const permission = "terminal.connect";
const purpose = "relay.agent.connect";
const maximumBodyBytes = 1024;
const maximumLifetimeSeconds = 120;

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

function signingKeyPEM(): string {
  const der = Deno.env.get("WEDECENT_CONNECTION_GRANT_PKCS8_B64")?.trim();
  if (!der || !/^[A-Za-z0-9+/=]+$/.test(der)) {
    throw new Error("WEDECENT_CONNECTION_GRANT_PKCS8_B64 is not configured");
  }
  const lines = der.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----`;
}

let signerPromise: Promise<{ key: CryptoKey; kid: string }> | null = null;

async function signer(): Promise<{ key: CryptoKey; kid: string }> {
  if (!signerPromise) {
    signerPromise = (async () => {
      const key = await importPKCS8(signingKeyPEM(), "EdDSA", { extractable: true });
      const jwk = await exportJWK(key);
      const kid = await calculateJwkThumbprint(jwk, "sha256");
      return { key, kid };
    })();
  }
  return signerPromise;
}

function parseDeviceID(value: unknown, field: string): string {
  if (typeof value !== "string" || !deviceIDPattern.test(value)) {
    throw new Error(`invalid ${field}`);
  }
  return value;
}

function rowObject(value: unknown): Record<string, unknown> | null {
  if (Array.isArray(value)) return value.length > 0 ? value[0] as Record<string, unknown> : null;
  if (value && typeof value === "object") return value as Record<string, unknown>;
  return null;
}

async function readBody(request: Request): Promise<Record<string, unknown>> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null) {
    if (!/^[0-9]+$/.test(declared)) throw new Error("invalid request body");
    const length = Number(declared);
    if (!Number.isSafeInteger(length)) throw new Error("invalid request body");
    if (length > maximumBodyBytes) throw new Error("request body too large");
  }

  const reader = request.body?.getReader();
  if (!reader) throw new Error("invalid request body");
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
        throw new Error("request body too large");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof Error && error.message === "request body too large") throw error;
    throw new Error("invalid request body");
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Request parsing remains fail-closed if the stream lock cannot be released.
    }
  }
  if (total === 0 || (declared !== null && Number(declared) !== total)) {
    throw new Error("invalid request body");
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
    throw new Error("invalid request body");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("invalid request body");
  }
  return parsed as Record<string, unknown>;
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

    const body = await readBody(req);
    const clientDeviceID = parseDeviceID(body.client_device_id, "client_device_id");
    const targetDeviceID = parseDeviceID(body.target_device_id, "target_device_id");
    const slot = body.slot;
    if (typeof slot !== "number" || !Number.isSafeInteger(slot) || slot < 1 || slot > 32) {
      return json({ error: "invalid agent slot" }, 400);
    }
    if (clientDeviceID === targetDeviceID) {
      return json({ error: "client and target devices must differ" }, 400);
    }

    const signing = await signer();
    const { data, error } = await admin.rpc("issue_connection_grant", {
      p_user_id: authData.user.id,
      p_client_device_id: clientDeviceID,
      p_target_device_id: targetDeviceID,
    });
    if (error) {
      console.warn("agent admission rejected", { code: error.code, message: error.message });
      return json({ error: "agent admission could not be issued" }, error.code === "42501" ? 403 : 409);
    }

    const row = rowObject(data);
    if (!row) throw new Error("agent admission RPC returned no row");

    const grantID = String(row.id ?? "");
    const jti = String(row.jti ?? "");
    const organizationID = row.organization_id == null ? null : String(row.organization_id);
    const issuedAtMS = Date.parse(String(row.issued_at ?? ""));
    const expiresAtMS = Date.parse(String(row.expires_at ?? ""));
    if (
      !uuidPattern.test(grantID) ||
      !uuidPattern.test(jti) ||
      (organizationID !== null && !uuidPattern.test(organizationID)) ||
      String(row.permission ?? "") !== permission ||
      !Number.isFinite(issuedAtMS) ||
      !Number.isFinite(expiresAtMS)
    ) {
      throw new Error("agent admission RPC returned invalid claims");
    }

    const issuedAt = Math.floor(issuedAtMS / 1000);
    const expiresAt = Math.floor(expiresAtMS / 1000);
    if (expiresAt <= issuedAt || expiresAt - issuedAt > maximumLifetimeSeconds) {
      throw new Error("agent admission RPC returned an invalid lifetime");
    }

    const agentAdmission = await new SignJWT({
      grant_id: grantID,
      organization_id: organizationID,
      client_device_id: clientDeviceID,
      target_device_id: targetDeviceID,
      permission,
      purpose,
      slot: Number(slot),
    })
      .setProtectedHeader({ alg: "EdDSA", typ: "JWT", kid: signing.kid })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject(authData.user.id)
      .setJti(jti)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAt)
      .sign(signing.key);

    return json({
      agent_admission: agentAdmission,
      claims: {
        grant_id: grantID,
        jti,
        user_id: authData.user.id,
        organization_id: organizationID,
        client_device_id: clientDeviceID,
        target_device_id: targetDeviceID,
        permission,
        purpose,
        slot: Number(slot),
        issued_at: new Date(issuedAtMS).toISOString(),
        expires_at: new Date(expiresAtMS).toISOString(),
        kid: signing.kid,
      },
    });
  } catch (err) {
    console.error("agent-admission failed", err);
    const message = err instanceof Error ? err.message : "internal error";
    if (message.startsWith("invalid ")) return json({ error: message }, 400);
    if (message === "request body too large") return json({ error: message }, 413);
    return json({ error: "internal error" }, 500);
  }
});
