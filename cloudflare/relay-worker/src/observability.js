import { relayRateLimitConfig } from "./rate-limit.js";

const HEALTH_OBJECT_NAME = "health-v1";
const HEALTH_URL = "https://wedecent.internal/health";
const TRACE_HEADER = "X-WeDecent-Trace-ID";
const MAX_DURATION_MS = 24 * 60 * 60 * 1000;

export function relayMetricContext(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;
  let route = "not_found";
  if (pathname === "/healthz") route = "health";
  else if (pathname === "/readyz") route = "ready";
  else if (pathname === "/v1/time") route = "time";
  else if (pathname.startsWith("/v1/direct-authorize/")) route = "direct_authorize";
  else if (pathname.startsWith("/v1/status/")) route = "status";
  else if (pathname.startsWith("/v1/stream/")) route = "stream";

  let role = "none";
  if (route === "stream") {
    const requestedRole = url.searchParams.get("role");
    if (requestedRole === "agent" || requestedRole === "client") {
      role = requestedRole;
    }
  }
  return { route, role };
}

export function recordRelayMetric(env, context, response, durationMS) {
  writeMetric(env, context, response.status, metricOutcome(response.status), durationMS);
}

export function recordRelayException(env, context, durationMS) {
  writeMetric(env, context, 500, "exception", durationMS);
}

export function emitRelayTrace(log, context, traceID, status, durationMS, outcome = metricOutcome(status)) {
  if (typeof log !== "function") {
    return;
  }
  const event = {
    event: "relay_request",
    trace_id: traceID,
    route: context.route,
    role: context.role,
    status,
    outcome,
    duration_ms: safeDuration(durationMS),
  };
  try {
    log(JSON.stringify(event));
  } catch {
    // Logging must never alter relay availability or authorization behavior.
  }
}

export function withRelayTraceHeader(response, traceID) {
  if (response.status === 101) {
    return response;
  }
  const headers = new Headers(response.headers);
  headers.set(TRACE_HEADER, traceID);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export async function relayReadiness(env) {
  try {
    relayRateLimitConfig(env ?? {});
    if (!env?.RELAY_METRICS || typeof env.RELAY_METRICS.writeDataPoint !== "function") {
      return false;
    }
    const checks = [probeDurableObject(env.DEVICE_RELAY), probeDurableObject(env.RELAY_RATE_LIMIT)];
    const results = await Promise.all(checks);
    return results.every(Boolean);
  } catch {
    return false;
  }
}

export function healthProbeRequest(request) {
  if (request.method !== "GET") {
    return false;
  }
  return new URL(request.url).pathname === "/health";
}

export function metricOutcome(status) {
  if (status >= 500) return "server_error";
  if (status === 429) return "rate_limited";
  if (status >= 400) return "rejected";
  if (status === 101) return "upgraded";
  return "success";
}

function writeMetric(env, context, status, outcome, durationMS) {
  const writer = env?.RELAY_METRICS;
  if (!writer || typeof writer.writeDataPoint !== "function") {
    return;
  }
  try {
    writer.writeDataPoint({
      indexes: [context.route],
      blobs: [context.route, context.role, String(status), outcome],
      doubles: [1, safeDuration(durationMS)],
    });
  } catch {
    // Telemetry must never alter relay availability or authorization behavior.
  }
}

function safeDuration(durationMS) {
  if (!Number.isFinite(durationMS)) {
    return 0;
  }
  return Math.min(MAX_DURATION_MS, Math.max(0, Math.round(durationMS)));
}

async function probeDurableObject(namespace) {
  if (!namespace || typeof namespace.idFromName !== "function" || typeof namespace.get !== "function") {
    return false;
  }
  const objectId = namespace.idFromName(HEALTH_OBJECT_NAME);
  const stub = namespace.get(objectId);
  if (!stub || typeof stub.fetch !== "function") {
    return false;
  }
  const response = await stub.fetch(new Request(HEALTH_URL));
  return response.status === 204;
}
