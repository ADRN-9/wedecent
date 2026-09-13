import { createClient } from "npm:@supabase/supabase-js@2";
import {
  calculateJwkThumbprint,
  exportJWK,
  importPKCS8,
} from "npm:jose@6";

import {
  generateRouteAuthorizationJTI,
  MAX_ROUTE_AUTHORIZATION_COST,
  signRouteAuthorization,
} from "../_shared/route-authorization.mjs";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const deviceIDPattern = /^wd_[a-z2-7]{16}$/;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
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
  const der =
    Deno.env
      .get("WEDECENT_ROUTE_AUTHORIZATION_PKCS8_B64")
      ?.trim() ?? "";

  if (!der || !/^[A-Za-z0-9+/=]+$/.test(der)) {
    throw new Error(
      "WEDECENT_ROUTE_AUTHORIZATION_PKCS8_B64 is not configured",
    );
  }

  const lines = der.match(/.{1,64}/g) ?? [];

  return (
    "-----BEGIN PRIVATE KEY-----\n" +
    lines.join("\n") +
    "\n-----END PRIVATE KEY-----"
  );
}

let signerPromise:
  Promise<{ key: CryptoKey; kid: string }> | null = null;

async function signer():
  Promise<{ key: CryptoKey; kid: string }> {
  if (!signerPromise) {
    signerPromise = (async () => {
      const key = await importPKCS8(
        signingKeyPEM(),
        "EdDSA",
        { extractable: true },
      );

      const jwk = await exportJWK(key);
      const kid = await calculateJwkThumbprint(jwk, "sha256");

      return { key, kid };
    })();
  }

  return signerPromise;
}

function parseDeviceID(
  value: unknown,
  field: string,
): string {
  const deviceID = String(value ?? "").trim();

  if (!deviceIDPattern.test(deviceID)) {
    throw new Error(`invalid ${field}`);
  }

  return deviceID;
}

function parseTransport(
  value: unknown,
  field: string,
): string {
  const transport = String(value ?? "")
    .trim()
    .toLowerCase();

  if (
    transport !== "lan" &&
    transport !== "internet"
  ) {
    throw new Error(`invalid ${field}`);
  }

  return transport;
}

function parseCost(
  value: unknown,
  field: string,
): number {
  const cost = Number(value);

  if (
    !Number.isSafeInteger(cost) ||
    cost < 0 ||
    cost > MAX_ROUTE_AUTHORIZATION_COST
  ) {
    throw new Error(`invalid ${field}`);
  }

  return cost;
}

function rowObject(
  value: unknown,
): Record<string, unknown> | null {
  if (Array.isArray(value)) {
    return value.length > 0
      ? value[0] as Record<string, unknown>
      : null;
  }

  if (value && typeof value === "object") {
    return value as Record<string, unknown>;
  }

  return null;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", {
      headers: corsHeaders,
    });
  }

  if (req.method !== "POST") {
    return json({ error: "method not allowed" }, 405);
  }

  try {
    const authorization =
      req.headers.get("Authorization");

    const token =
      authorization
        ?.match(/^Bearer\s+(.+)$/i)?.[1];

    if (!token) {
      return json(
        { error: "authentication required" },
        401,
      );
    }

    const url = Deno.env.get("SUPABASE_URL");
    if (!url) {
      throw new Error(
        "SUPABASE_URL is not configured",
      );
    }

    const admin = createClient(
      url,
      serviceKey(),
      {
        auth: {
          persistSession: false,
          autoRefreshToken: false,
        },
      },
    );

    const {
      data: authData,
      error: authError,
    } = await admin.auth.getUser(token);

    if (authError || !authData.user) {
      return json(
        { error: "invalid user session" },
        401,
      );
    }

    const rawBody = await req.json();

    if (
      !rawBody ||
      typeof rawBody !== "object" ||
      Array.isArray(rawBody)
    ) {
      return json(
        { error: "invalid request body" },
        400,
      );
    }

    const body =
      rawBody as Record<string, unknown>;

    const sourceDeviceID = parseDeviceID(
      body.source_device_id,
      "source_device_id",
    );

    const routerDeviceID = parseDeviceID(
      body.router_device_id,
      "router_device_id",
    );

    const destinationDeviceID = parseDeviceID(
      body.destination_device_id,
      "destination_device_id",
    );

    if (
      sourceDeviceID === routerDeviceID ||
      sourceDeviceID === destinationDeviceID ||
      routerDeviceID === destinationDeviceID
    ) {
      return json(
        {
          error:
            "source, router, and destination devices must differ",
        },
        400,
      );
    }

    const firstTransport = parseTransport(
      body.first_transport,
      "first_transport",
    );

    const secondTransport = parseTransport(
      body.second_transport,
      "second_transport",
    );

    const firstCost = parseCost(
      body.first_cost,
      "first_cost",
    );

    const secondCost = parseCost(
      body.second_cost,
      "second_cost",
    );

    // Load the dedicated signer before creating an audit
    // row. A missing key must fail without leaving an
    // unsigned issuance record.
    const signing = await signer();

    const jti =
      generateRouteAuthorizationJTI();

    const { data, error } = await admin.rpc(
      "issue_route_authorization",
      {
        p_user_id: authData.user.id,
        p_jti: jti,
        p_source_device_id: sourceDeviceID,
        p_router_device_id: routerDeviceID,
        p_destination_device_id:
          destinationDeviceID,
        p_first_transport: firstTransport,
        p_second_transport: secondTransport,
        p_first_cost: firstCost,
        p_second_cost: secondCost,
      },
    );

    if (error) {
      console.warn(
        "route authorization rejected",
        {
          code: error.code,
          message: error.message,
        },
      );

      const status =
        error.code === "42501"
          ? 403
          : error.code === "22023"
            ? 400
            : 409;

      return json(
        {
          error:
            "route authorization could not be issued",
        },
        status,
      );
    }

    const row = rowObject(data);

    if (!row) {
      throw new Error(
        "route authorization RPC returned no row",
      );
    }

    const signed =
      await signRouteAuthorization(
        signing.key,
        signing.kid,
        row,
      );

    return json(signed);
  } catch (err) {
    console.error(
      "route-authorization failed",
      err,
    );

    const message =
      err instanceof Error
        ? err.message
        : "internal error";

    if (
      message.startsWith("invalid ")
    ) {
      return json({ error: message }, 400);
    }

    return json(
      { error: "internal error" },
      500,
    );
  }
});
