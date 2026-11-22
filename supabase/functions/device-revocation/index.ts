import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Cache-Control": "no-store",
};
const deviceIDPattern = /^wd_[a-z2-7]{16}$/;

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

async function readDeviceID(request: Request): Promise<string> {
  const maximumBytes = 1024;
  const declared = request.headers.get("Content-Length");
  if (declared !== null && (!/^[0-9]+$/.test(declared) || Number(declared) > maximumBytes)) {
    throw new Error("invalid request body");
  }
  const reader = request.body?.getReader();
  if (!reader) throw new Error("invalid request body");
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        void reader.cancel().catch(() => {});
        throw new Error("request body too large");
      }
      chunks.push(value);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // A failed release does not change the fail-closed request result.
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
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("invalid request body");
  }
  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    Object.keys(payload).length !== 1 ||
    typeof (payload as Record<string, unknown>).device_id !== "string" ||
    !deviceIDPattern.test((payload as Record<string, string>).device_id)
  ) {
    throw new Error("invalid device_id");
  }
  return (payload as Record<string, string>).device_id;
}

function bearerToken(request: Request): string {
  const match = /^Bearer ([^\s]+)$/.exec(request.headers.get("Authorization") ?? "");
  return match?.[1] ?? "";
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);

  try {
    const token = bearerToken(request);
    if (!token) return json({ error: "authentication required" }, 401);

    const supabaseURL = Deno.env.get("SUPABASE_URL");
    if (!supabaseURL) throw new Error("SUPABASE_URL is not configured");
    const admin = createClient(supabaseURL, serviceKey(), {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: authData, error: authError } = await admin.auth.getUser(token);
    if (authError || !authData.user) return json({ error: "authentication rejected" }, 401);

    let deviceID: string;
    try {
      deviceID = await readDeviceID(request);
    } catch {
      return json({ error: "invalid device_id" }, 400);
    }
    const { data: device, error: deviceError } = await admin
      .from("devices")
      .select("device_id, owner_user_id, organization_id, revoked_at")
      .eq("device_id", deviceID)
      .maybeSingle();
    if (deviceError) throw new Error("device lookup failed");
    if (!device) return json({ error: "device not found" }, 404);

    if (device.owner_user_id !== authData.user.id) {
      if (!device.organization_id) return json({ error: "device revocation not authorized" }, 403);
      const { data: membership, error: membershipError } = await admin
        .from("organization_memberships")
        .select("role")
        .eq("organization_id", device.organization_id)
        .eq("user_id", authData.user.id)
        .maybeSingle();
      if (membershipError) throw new Error("organization authorization lookup failed");
      if (!membership || !["owner", "admin"].includes(membership.role)) {
        return json({ error: "device revocation not authorized" }, 403);
      }
    }

    if (device.revoked_at === null) {
      const { error: revokeError } = await admin
        .from("devices")
        .update({ revoked_at: new Date().toISOString() })
        .eq("device_id", deviceID)
        .is("revoked_at", null);
      if (revokeError) throw new Error("device revocation could not be persisted");
    }

    const { data: dispatch, error: dispatchLookupError } = await admin
      .from("device_revocation_dispatch_outbox")
      .select("id, status, attempts")
      .eq("device_id", deviceID)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    if (dispatchLookupError) throw new Error("device revocation dispatch lookup failed");

    let dispatchRecord = dispatch;
    if (!dispatchRecord) {
      const { data: createdDispatch, error: createDispatchError } = await admin
        .from("device_revocation_dispatch_outbox")
        .insert({ device_id: deviceID, status: "pending" })
        .select("id, status, attempts")
        .single();
      if (createDispatchError || !createdDispatch) {
        throw new Error("device revocation dispatch could not be queued");
      }
      dispatchRecord = createdDispatch;
    }
    if (dispatchRecord.status === "dispatched") {
      return json({ revoked: true, device_id: deviceID, relay: { already_dispatched: true } });
    }
    if (dispatchRecord.status !== "pending") {
      throw new Error("device revocation dispatch state is invalid");
    }

    const recordDispatchFailure = async (reason: string) => {
      const { error: attemptError } = await admin
        .from("device_revocation_dispatch_outbox")
        .update({
          attempts: dispatchRecord.attempts + 1,
          last_attempt_at: new Date().toISOString(),
          last_error: reason,
        })
        .eq("id", dispatchRecord.id)
        .eq("status", "pending");
      if (attemptError) throw new Error("device revocation dispatch attempt could not be recorded");
    };

    const relayURL = Deno.env.get("WEDECENT_RELAY_REVOCATION_URL")?.trim() ?? "";
    const relayToken = Deno.env.get("WEDECENT_RELAY_REVOCATION_TOKEN") ?? "";
    if (!relayURL || !relayToken || relayToken.length < 32) {
      await recordDispatchFailure("relay_configuration_missing");
      return json({
        error: "device is revoked; relay session termination is pending operator configuration",
      }, 503);
    }

    let endpoint: URL;
    try {
      endpoint = new URL(relayURL);
    } catch {
      await recordDispatchFailure("relay_endpoint_invalid");
      return json({ error: "device is revoked; relay session termination is pending retry" }, 503);
    }
    if (
      endpoint.protocol !== "https:" ||
      endpoint.username !== "" ||
      endpoint.password !== "" ||
      endpoint.pathname !== "/" ||
      endpoint.search !== "" ||
      endpoint.hash !== ""
    ) {
      await recordDispatchFailure("relay_endpoint_invalid");
      return json({ error: "device is revoked; relay session termination is pending retry" }, 503);
    }

    let relayResponse: Response;
    try {
      relayResponse = await fetch(
        endpoint.origin + "/v1/revoke/" + encodeURIComponent(deviceID),
        {
          method: "POST",
          headers: {
            Authorization: "Bearer " + relayToken,
            "Cache-Control": "no-store",
          },
          redirect: "error",
        },
      );
    } catch {
      await recordDispatchFailure("relay_dispatch_failed");
      return json({
        error: "device is revoked; relay session termination is pending retry",
      }, 503);
    }
    if (!relayResponse.ok) {
      await recordDispatchFailure("relay_dispatch_failed");
      return json({
        error: "device is revoked; relay session termination is pending retry",
      }, 503);
    }

    const dispatchedAt = new Date().toISOString();
    const { error: completeError } = await admin
      .from("device_revocation_dispatch_outbox")
      .update({
        status: "dispatched",
        attempts: dispatchRecord.attempts + 1,
        last_attempt_at: dispatchedAt,
        dispatched_at: dispatchedAt,
        last_error: null,
      })
      .eq("id", dispatchRecord.id)
      .eq("status", "pending");
    if (completeError) throw new Error("device revocation dispatch completion could not be recorded");

    const relayResult = await relayResponse.json().catch(() => null);
    return json({
      revoked: true,
      device_id: deviceID,
      relay: relayResult,
    });

  } catch (error) {
    console.error("device-revocation unavailable", error);
    return json({ error: "device revocation service unavailable" }, 503);
  }
});
