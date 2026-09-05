import { createClient } from "npm:@supabase/supabase-js@2";
import { calculateJwkThumbprint, exportJWK, importPKCS8, SignJWT } from "npm:jose@6";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const deviceIDPattern = /^wd_[a-z2-7]{16}$/;
const issuer = "wedecent-control-plane";
const audience = "wedecent-relay";

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
      // jose v6 imports private CryptoKeys as non-extractable by default. We
      // export this key to JWK only to derive the stable RFC 7638 `kid`, so the
      // import must explicitly be extractable. The raw PKCS#8 material is
      // already present only inside this trusted Edge Function environment.
      const key = await importPKCS8(signingKeyPEM(), "EdDSA", { extractable: true });
      const jwk = await exportJWK(key);
      const kid = await calculateJwkThumbprint(jwk, "sha256");
      return { key, kid };
    })();
  }
  return signerPromise;
}

function parseDeviceID(value: unknown, field: string): string {
  const deviceID = String(value ?? "");
  if (!deviceIDPattern.test(deviceID)) throw new Error(`invalid ${field}`);
  return deviceID;
}

function rowObject(value: unknown): Record<string, unknown> | null {
  if (Array.isArray(value)) return value.length > 0 ? value[0] as Record<string, unknown> : null;
  if (value && typeof value === "object") return value as Record<string, unknown>;
  return null;
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
    const clientDeviceID = parseDeviceID(body.client_device_id, "client_device_id");
    const targetDeviceID = parseDeviceID(body.target_device_id, "target_device_id");
    if (clientDeviceID === targetDeviceID) return json({ error: "client and target devices must differ" }, 400);

    // Load the signing key before creating an audit row so a configuration error
    // cannot leave a grant record that was never capable of being signed.
    const signing = await signer();

    const { data, error } = await admin.rpc("issue_connection_grant", {
      p_user_id: userId,
      p_client_device_id: clientDeviceID,
      p_target_device_id: targetDeviceID,
    });
    if (error) {
      console.warn("connection grant rejected", { code: error.code, message: error.message });
      const status = error.code === "42501" ? 403 : 409;
      return json({ error: "connection grant could not be issued" }, status);
    }

    const row = rowObject(data);
    if (!row) throw new Error("connection grant RPC returned no row");

    const grantID = String(row.id ?? "");
    const jti = String(row.jti ?? "");
    const organizationID = row.organization_id == null ? null : String(row.organization_id);
    const permission = String(row.permission ?? "");
    const issuedAtMS = Date.parse(String(row.issued_at ?? ""));
    const expiresAtMS = Date.parse(String(row.expires_at ?? ""));
    if (!grantID || !jti || permission !== "terminal.connect" || !Number.isFinite(issuedAtMS) || !Number.isFinite(expiresAtMS)) {
      throw new Error("connection grant RPC returned invalid claims");
    }

    const issuedAt = Math.floor(issuedAtMS / 1000);
    const expiresAt = Math.floor(expiresAtMS / 1000);
    const jwt = await new SignJWT({
      grant_id: grantID,
      organization_id: organizationID,
      client_device_id: clientDeviceID,
      target_device_id: targetDeviceID,
      permission,
    })
      .setProtectedHeader({ alg: "EdDSA", typ: "JWT", kid: signing.kid })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject(userId)
      .setJti(jti)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAt)
      .sign(signing.key);

    return json({
      grant: jwt,
      claims: {
        grant_id: grantID,
        jti,
        user_id: userId,
        organization_id: organizationID,
        client_device_id: clientDeviceID,
        target_device_id: targetDeviceID,
        permission,
        issued_at: new Date(issuedAtMS).toISOString(),
        expires_at: new Date(expiresAtMS).toISOString(),
        kid: signing.kid,
      },
    });
  } catch (err) {
    console.error("connection-grant failed", err);
    const message = err instanceof Error ? err.message : "internal error";
    if (message.startsWith("invalid ")) return json({ error: message }, 400);
    return json({ error: "internal error" }, 500);
  }
});
