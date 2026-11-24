import { createClient } from "npm:@supabase/supabase-js@2";
import {
  canonicalPortForwardAuthorizationMessage,
  decodeBase64URLStrict,
  deviceIDFromPublicKey,
  encodeBase64URL,
  remoteReplayDeviceMessage,
  verifyRouteAuthorizationBinding,
} from "../_shared/port-forward-replay.mjs";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const deviceIDPattern = /^wd_[a-z2-7]{16}$/;
const digestPattern = /^[0-9a-f]{64}$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

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
  throw new Error("Supabase service role key is not configured");
}

function controlPlanePublicKey(): Uint8Array {
  const value = Deno.env.get("WEDECENT_PORT_FORWARD_AUTHORIZATION_PUBLIC_KEY_B64URL")?.trim() ?? "";
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error("WEDECENT_PORT_FORWARD_AUTHORIZATION_PUBLIC_KEY_B64URL is not configured");
  }
  return decodeBase64URLStrict(value, 32);
}

function routeAuthorizationPublicKey(): Uint8Array {
  const value = Deno.env.get("WEDECENT_ROUTE_AUTHORIZATION_PUBLIC_KEY_B64URL")?.trim() ?? "";
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error("WEDECENT_ROUTE_AUTHORIZATION_PUBLIC_KEY_B64URL is not configured");
  }
  return decodeBase64URLStrict(value, 32);
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function rowObject(value: unknown): Record<string, unknown> | null {
  if (Array.isArray(value)) return value.length ? value[0] as Record<string, unknown> : null;
  if (value && typeof value === "object") return value as Record<string, unknown>;
  return null;
}

async function authorizationDigest(
  authorization: Record<string, unknown>,
  publicKeyBytes: Uint8Array,
): Promise<{
  jti: string; issuedAtUnixMS: number; expiresAtUnixMS: number;
  forwardingID: string; direction: string; initiatingDevice: string;
  destinationDevice: string; routerDevice: string | null;
  route: Record<string, unknown>; digestHex: string;
}> {
  const claims = authorization.claims as Record<string, unknown>;
  const canonical = canonicalPortForwardAuthorizationMessage(authorization);
  const signature = decodeBase64URLStrict(authorization.signature as string, 64);
  const keyDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(publicKeyBytes)));
  const expectedKid = "ed25519-" + encodeBase64URL(keyDigest);
  if (authorization.kid !== expectedKid) throw new Error("authorization key identifier mismatch");
  const key = await crypto.subtle.importKey("raw", asArrayBuffer(publicKeyBytes), { name: "Ed25519" }, false, ["verify"]);
  if (!await crypto.subtle.verify({ name: "Ed25519" }, key, asArrayBuffer(signature), asArrayBuffer(canonical))) {
    throw new Error("control-plane authorization signature rejected");
  }
  const issued = claims.iat_unix_ms as number;
  const expires = claims.exp_unix_ms as number;
  const now = Date.now();
  if (issued > now || expires <= now || expires - now > 120000) {
    throw new Error("authorization is not currently valid");
  }
  const digestInput = new Uint8Array(canonical.length + signature.length);
  digestInput.set(canonical);
  digestInput.set(signature, canonical.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(digestInput)));
  const forwardingID = String(claims.forwarding_id ?? "");
  const direction = String(claims.direction ?? "");
  const initiatingDevice = String(claims.initiating_device ?? "");
  const destinationDevice = String(claims.destination_device ?? "");
  const routerDevice = claims.router == null ? null : String(claims.router);
  if (!uuidPattern.test(forwardingID) || !["local", "remote"].includes(direction) ||
      !deviceIDPattern.test(initiatingDevice) || !deviceIDPattern.test(destinationDevice) ||
      (routerDevice !== null && !deviceIDPattern.test(routerDevice))) {
    throw new Error("authorization participant context is invalid");
  }
  return {
    jti: claims.jti as string,
    issuedAtUnixMS: issued,
    expiresAtUnixMS: expires,
    forwardingID,
    direction,
    initiatingDevice,
    destinationDevice,
    routerDevice,
    route: claims.route as Record<string, unknown>,
    digestHex: Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join(""),
  };
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
  if (!request.headers.get("apikey")) return json({ error: "Data API key required" }, 401);

  try {
    const raw = await request.json();
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return json({ error: "invalid request" }, 400);
    const body = raw as Record<string, unknown>;
    if (Object.keys(body).some((key) => !["device_id", "authorization", "authorization_sha256", "device_signature"].includes(key))) {
      return json({ error: "unexpected request field" }, 400);
    }
    const deviceID = String(body.device_id ?? "");
    if (!deviceIDPattern.test(deviceID)) return json({ error: "invalid device_id" }, 400);
    if (!digestPattern.test(String(body.authorization_sha256 ?? ""))) return json({ error: "invalid authorization digest" }, 400);
    if (!body.authorization || typeof body.authorization !== "object" || Array.isArray(body.authorization)) {
      return json({ error: "authorization is required" }, 400);
    }
    const authorization = body.authorization as Record<string, unknown>;
    const claims = authorization.claims as Record<string, unknown>;
    if (!claims || typeof claims !== "object" || Array.isArray(claims)) return json({ error: "authorization claims are required" }, 400);
    if (deviceID !== claims.initiating_device && deviceID !== claims.destination_device) {
      return json({ error: "device is not an authorization endpoint" }, 403);
    }

    const publicKeyBytes = controlPlanePublicKey();
    const verified = await authorizationDigest(authorization, publicKeyBytes);
    if (body.authorization_sha256 !== verified.digestHex) return json({ error: "authorization digest mismatch" }, 400);
    const routeBinding = await verifyRouteAuthorizationBinding(
      authorization,
      claims,
      verified.routerDevice === null ? new Uint8Array() : routeAuthorizationPublicKey(),
    );

    const url = Deno.env.get("SUPABASE_URL");
    if (!url) throw new Error("SUPABASE_URL is not configured");
    const admin = createClient(url, serviceKey(), {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: device, error: deviceError } = await admin
      .from("devices")
      .select("public_key, revoked_at")
      .eq("device_id", deviceID)
      .maybeSingle();
    if (deviceError) throw deviceError;
    if (!device || device.revoked_at) return json({ error: "device is not active" }, 403);
    if (typeof device.public_key !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(device.public_key)) {
      throw new Error("enrolled device public key is invalid");
    }

    const devicePublicKey = decodeBase64URLStrict(device.public_key, 32);
    if (await deviceIDFromPublicKey(devicePublicKey) !== deviceID) {
      return json({ error: "enrolled device key does not match device identity" }, 403);
    }
    const deviceKey = await crypto.subtle.importKey("raw", asArrayBuffer(devicePublicKey), { name: "Ed25519" }, false, ["verify"]);
    const deviceSignature = decodeBase64URLStrict(String(body.device_signature ?? ""), 64);
    const proof = remoteReplayDeviceMessage(deviceID, verified.jti, verified.expiresAtUnixMS, verified.digestHex);
    if (!await crypto.subtle.verify({ name: "Ed25519" }, deviceKey, asArrayBuffer(deviceSignature), asArrayBuffer(proof))) {
      return json({ error: "device replay proof rejected" }, 403);
    }

    const { data, error } = await admin.rpc("consume_port_forward_authorization", {
      p_device_id: deviceID,
      p_device_public_key: device.public_key,
      p_forwarding_id: verified.forwardingID,
      p_direction: verified.direction,
      p_initiating_device_id: verified.initiatingDevice,
      p_destination_device_id: verified.destinationDevice,
      p_router_device_id: verified.routerDevice,
      p_route_authorization_id: routeBinding?.id ?? null,
      p_route_authorization_jti: routeBinding?.jti ?? null,
      p_route_source_device_id: routeBinding?.sourceDeviceID ?? null,
      p_route_destination_device_id: routeBinding?.destinationDeviceID ?? null,
      p_route_first_transport: routeBinding?.firstTransport ?? null,
      p_route_second_transport: routeBinding?.secondTransport ?? null,
      p_route_first_cost: routeBinding?.firstCost ?? null,
      p_route_second_cost: routeBinding?.secondCost ?? null,
      p_jti: verified.jti,
      p_issued_at: new Date(verified.issuedAtUnixMS).toISOString(),
      p_expires_at: new Date(verified.expiresAtUnixMS).toISOString(),
      p_authorization_sha256: `\\x${verified.digestHex}`,
    });
    if (error) {
      console.error("port-forward replay authority rejected", { code: error.code });
      const status = error.code === "42501" ? 403 : error.code === "22023" ? 400 : error.code === "40001" ? 409 : 503;
      return json({ error: status === 503 ? "independent replay authority unavailable" : "authorization context rejected" }, status);
    }
    const result = rowObject(data);
    if (!result || typeof result.accepted !== "boolean") throw new Error("replay RPC returned malformed state");
    if (!result.accepted) return json({ accepted: false, reason: result.reason ?? "replay" }, 409);
    const generation = String(result.generation ?? "");
    const stateHash = String(result.state_hash ?? "");
    if (!/^[1-9][0-9]{0,18}$/.test(generation) || !digestPattern.test(stateHash)) {
      throw new Error("replay RPC returned invalid authority state");
    }
    return json({ accepted: true, replayed: result.replayed === true, generation, state_hash: stateHash });
  } catch (error) {
    console.error("port-forward-replay failed", error);
    const message = error instanceof Error ? error.message : "invalid request";
    if (message.startsWith("invalid port-forward replay authorization:") || message.includes("authorization") || message.includes("device")) {
      return json({ error: "authorization or device proof rejected" }, 403);
    }
    return json({ error: "independent replay authority unavailable" }, 503);
  }
});
