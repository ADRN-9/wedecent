import { createClient } from "npm:@supabase/supabase-js@2";
import { dispatchPendingDeviceRevocations } from "../_shared/device-revocation-dispatch.mjs";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
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

function constantTimeEqual(left: string, right: string): boolean {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index++) difference |= a[index] ^ b[index];
  return difference === 0;
}

Deno.serve(async (request) => {
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
  const expected = Deno.env.get("WEDECENT_REVOCATION_DISPATCH_TOKEN") ?? "";
  const match = /^Bearer ([^\s]+)$/.exec(request.headers.get("Authorization") ?? "");
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(expected) || !match || !constantTimeEqual(match[1], expected)) {
    return json({ error: "authentication rejected" }, 401);
  }

  try {
    const supabaseURL = Deno.env.get("SUPABASE_URL");
    if (!supabaseURL) throw new Error("SUPABASE_URL is not configured");
    const admin = createClient(supabaseURL, serviceKey(), {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const result = await dispatchPendingDeviceRevocations(admin, {
      relayURL: Deno.env.get("WEDECENT_RELAY_REVOCATION_URL") ?? "",
      relayToken: Deno.env.get("WEDECENT_RELAY_REVOCATION_TOKEN") ?? "",
      limit: 20,
    });
    return json(result);
  } catch (error) {
    console.error("device-revocation-dispatch unavailable", error);
    return json({ error: "device revocation dispatcher unavailable" }, 503);
  }
});
