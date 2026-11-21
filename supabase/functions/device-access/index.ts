import { createClient } from "npm:@supabase/supabase-js@2";
import { withBoundedDatabaseRetry } from "../_shared/database-rpc-retry.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const deviceIDPattern = /^wd_[a-z2-7]{16}$/;
const uuidPattern = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
const expiryPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

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
  throw new Error("Supabase service key is not configured");
}

function publicKey(): string {
  const key = Deno.env.get("SUPABASE_ANON_KEY") ??
    Deno.env.get("SUPABASE_PUBLISHABLE_KEY");
  if (!key) throw new Error("Supabase anon or publishable key is not configured");
  return key;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseDeviceID(value: unknown): string {
  const deviceID = String(value ?? "").trim();
  if (!deviceIDPattern.test(deviceID)) throw new Error("invalid device_id");
  return deviceID;
}

function parseGranteeID(value: unknown): string {
  const granteeID = String(value ?? "").trim();
  if (!uuidPattern.test(granteeID)) throw new Error("invalid grantee_user_id");
  return granteeID;
}

function parseExpiry(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || !expiryPattern.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new Error("invalid expires_at");
  }
  return value;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  try {
    const token = req.headers.get("Authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (!token) return json({ error: "authentication required" }, 401);

    const url = Deno.env.get("SUPABASE_URL");
    if (!url) throw new Error("SUPABASE_URL is not configured");

    const admin = createClient(url, serviceKey(), {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: authData, error: authError } = await admin.auth.getUser(token);
    if (authError || !authData.user) return json({ error: "invalid user session" }, 401);
    if (authData.user.is_anonymous) {
      return json({ error: "permanent authenticated identity required" }, 403);
    }

    const rawBody = await req.json();
    if (!isRecord(rawBody)) return json({ error: "invalid request body" }, 400);

    if (
      "actor_id" in rawBody ||
      "actor_user_id" in rawBody ||
      "granted_by" in rawBody ||
      "p_actor_user_id" in rawBody ||
      "p_granted_by" in rawBody
    ) {
      return json({ error: "actor identity is derived from the authenticated session" }, 400);
    }

    const action = rawBody.action;
    if (action !== "create" && action !== "update_expiry" && action !== "revoke") {
      return json({ error: "invalid action" }, 400);
    }

    const deviceID = parseDeviceID(rawBody.device_id);
    const granteeID = parseGranteeID(rawBody.grantee_user_id);
    if (rawBody.permission !== "terminal.connect") throw new Error("invalid permission");

    const args = {
      p_device_id: deviceID,
      p_grantee_user_id: granteeID,
      p_permission: "terminal.connect",
    };

    let rpcName: string;
    let rpcArgs: Record<string, unknown>;

    if (action === "create" || action === "update_expiry") {
      if (!Object.prototype.hasOwnProperty.call(rawBody, "expires_at")) {
        throw new Error("expires_at must be supplied explicitly; use null for a permanent grant");
      }
      const expiresAt = parseExpiry(rawBody.expires_at);
      rpcName = action === "create"
        ? "create_device_access_grant"
        : "update_device_access_grant_expiry";
      rpcArgs = { ...args, p_expires_at: expiresAt };
    } else {
      rpcName = "revoke_device_access_grant";
      rpcArgs = args;
    }

    // Forward the verified user's JWT. The RPC reads auth.uid(); the service
    // credential is used only for auth.getUser and never for table mutation.
    const userClient = createClient(url, publicKey(), {
      global: { headers: { Authorization: "Bearer " + token } },
      auth: { persistSession: false, autoRefreshToken: false },
    });

    const result = await withBoundedDatabaseRetry(
      () => userClient.rpc(rpcName, rpcArgs),
      { maxAttempts: 3, baseDelayMs: 20 },
    );

    if (result.error) {
      const code = result.error.code ?? "";
      console.warn("device-access RPC rejected", { action, code });
      const status = code === "42501"
        ? 403
        : code === "22023"
          ? 400
          : code === "P0002"
            ? 404
            : code === "40001" || code === "40P01"
              ? 503
              : code === "23505"
                ? 409
                : 409;
      return json({ error: "device access operation could not be completed", code }, status);
    }

    return json({ action, grant: result.data });
  } catch (error) {
    const message = error instanceof Error ? error.message : "internal error";
    if (message.startsWith("invalid ") || message.startsWith("expires_at")) {
      return json({ error: message }, 400);
    }
    console.error("device-access failed", error);
    return json({ error: "internal error" }, 500);
  }
});
