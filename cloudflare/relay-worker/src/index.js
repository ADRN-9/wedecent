import { DurableObject } from "cloudflare:workers";
import { authorizeStream, AGENT_ADMISSION_HEADER, CONNECTION_GRANT_HEADER } from "./stream-auth.js";
import {
  agentAdmissionReplayMetadataFromRequest,
  cleanupExpiredConnectionGrants,
  consumeAgentAdmission,
  consumeConnectionGrant,
  INTERNAL_AGENT_LEGACY_HEADER,
  INTERNAL_CLIENT_DEVICE_ID_HEADER,
  INTERNAL_GRANT_EXP_HEADER,
  INTERNAL_GRANT_JTI_HEADER,
  prepareAgentRelayRequest,
  prepareDeviceRelayRequest,
  relayTicketReplayMetadataFromRequest,
  replayMetadataFromRequest,
  scheduleReplayCleanup,
} from "./grant-replay.js";
import { planAgentSlotAdmission } from "./agent-slots.js";
import {
  agentSessionExpired,
  createAgentSessionAttachment,
  MAX_AGENT_SESSION_LIFETIME_MS,
  nextAgentSessionExpiry,
  touchAgentSessionAttachment,
} from "./agent-session-policy.js";
import { directAuthorizationPreflight, readBoundedRequestBody } from "./http-validation.js";
import {
  emitRelayTrace,
  healthProbeRequest,
  recordRelayException,
  recordRelayMetric,
  relayMetricContext,
  relayReadiness,
  withRelayTraceHeader,
} from "./observability.js";
import {
  acquireGlobalAgentConnectionLease,
  agentConnectionLeaseRequestConfig,
  agentRevocationTargets,
  bindGlobalAgentClient,
  registerGlobalDeviceAuthorizationGeneration,
  registerGlobalDeviceAuthorizationGenerationLease,
  isGlobalDeviceAuthorizationGenerationCurrent,
  bindGlobalAgentClientLease,
  cleanupExpiredDeviceRevocationMarkers,
  cleanupExpiredRateLimitBuckets,
  completeDeviceRevocationLease,
  cleanupGlobalAgentConnectionLeases,
  consumeRateLimitBuckets,
  RATE_LIMIT_CLEANUP_INTERVAL_MS,
  enforceRelayDeviceRateLimit,
  enforceRelayRequestRateLimit,
  limiterRequestConfig,
  releaseGlobalAgentConnection,
  releaseGlobalAgentConnectionLease,
  reserveGlobalAgentConnection,
  findAgentRevocationTargets,
  isGlobalDeviceRevoked,
  isGlobalDeviceRevokedLease,
  isGlobalDeviceAuthorizationGenerationCurrentLease,
  markGlobalDeviceRevoked,
  markGlobalDeviceRevokedLease,
  queueDeviceRevocationLease,
  retryPendingDeviceRevocations,
  completeGlobalDeviceRevocation,
  unbindGlobalAgentClient,
  unbindGlobalAgentClientLease,
} from "./rate-limit.js";

const DEVICE_ID = /^wd_[a-z2-7]{16}$/;
const STREAM_PREFIX = "/v1/stream/";
const STATUS_PREFIX = "/v1/status/";
const TIME_PATH = "/v1/time";
const DIRECT_AUTHORIZE_PREFIX = "/v1/direct-authorize/";
const DEVICE_REVOCATION_PREFIX = "/v1/revoke/";
const DEVICE_GENERATION_PREFIX = "/v1/device-generation/";
const AGENT_LEASE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const AGENT_SLOT = /^(?:[1-9]|[12][0-9]|3[0-2])$/;
const HEALTH_VERSION = 13;

export default {
  async fetch(request, env) {
    const metricContext = relayMetricContext(request);
    const traceID = crypto.randomUUID();
    const startedAtMS = Date.now();

    try {
      const response = await handleRelayRequest(request, env);
      const durationMS = Date.now() - startedAtMS;
      recordRelayMetric(env, metricContext, response, durationMS);
      emitRelayTrace(console.log, metricContext, traceID, response.status, durationMS);
      return withRelayTraceHeader(response, traceID);
    } catch (error) {
      const durationMS = Date.now() - startedAtMS;
      recordRelayException(env, metricContext, durationMS);
      emitRelayTrace(console.error, metricContext, traceID, 500, durationMS, "exception");
      throw error;
    }
  },
};

async function handleRelayRequest(request, env) {
  const url = new URL(request.url);

  if (url.pathname === "/healthz") {
    if (request.method !== "GET") {
      return new Response("Method not allowed", { status: 405 });
    }
    return Response.json(
      { service: "wedecent-relay", status: "ok", version: HEALTH_VERSION },
      { headers: { "Cache-Control": "no-store" } },
    );
  }

  if (url.pathname === "/readyz") {
    if (request.method !== "GET") {
      return new Response("Method not allowed", { status: 405 });
    }
    const ready = await relayReadiness(env);
    return Response.json(
      { service: "wedecent-relay", status: ready ? "ready" : "not_ready", version: HEALTH_VERSION },
      { status: ready ? 200 : 503, headers: { "Cache-Control": "no-store" } },
    );
  }

  if (url.pathname === TIME_PATH) {
    if (request.method !== "GET") {
      return new Response("Method not allowed", { status: 405 });
    }
    return Response.json(
      { unix_ms: Date.now() },
      { headers: { "Cache-Control": "no-store, no-cache, must-revalidate", Pragma: "no-cache" } },
    );
  }

  if (url.pathname.startsWith(DEVICE_REVOCATION_PREFIX)) {
    return handleDeviceRevocation(request, env, url);
  }
  if (url.pathname.startsWith(DEVICE_GENERATION_PREFIX)) {
    return handleDeviceGeneration(request, env, url);
  }

  if (url.pathname.startsWith(DIRECT_AUTHORIZE_PREFIX)) {
    const preflight = directAuthorizationPreflight(request, url);
    if (!preflight.ok) {
      return preflight.response;
    }
    const admission = await enforceRelayRequestRateLimit(request, env, "direct");
    if (!admission.ok) {
      return rateLimitResponse(admission);
    }
    return authorizeDirectRequest(request, env, preflight.targetDeviceID);
  }

  if (!url.pathname.startsWith(STREAM_PREFIX) && !url.pathname.startsWith(STATUS_PREFIX)) {
    return new Response("Not found", { status: 404 });
  }

  if (url.pathname.startsWith(STATUS_PREFIX)) {
    if (!legacyAuthorized(request, env)) {
      return new Response(env.RELAY_ACCESS_TOKEN ? "Unauthorized" : "Relay admin token is not configured", {
        status: env.RELAY_ACCESS_TOKEN ? 401 : 503,
      });
    }
    if (request.method !== "GET") {
      return new Response("Method not allowed", { status: 405 });
    }
    const deviceId = decodeURIComponent(url.pathname.slice(STATUS_PREFIX.length));
    if (!DEVICE_ID.test(deviceId)) {
      return new Response("Invalid device ID", { status: 400 });
    }
    const objectId = env.DEVICE_RELAY.idFromName(deviceId);
    return env.DEVICE_RELAY.get(objectId).fetch(new Request("https://wedecent.internal/status"));
  }

  if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
    return new Response("WebSocket upgrade required", { status: 426 });
  }

  const deviceId = decodeURIComponent(url.pathname.slice(STREAM_PREFIX.length));
  if (!DEVICE_ID.test(deviceId)) {
    return new Response("Invalid device ID", { status: 400 });
  }

  const role = url.searchParams.get("role");
  if (role !== "agent" && role !== "client") {
    return new Response("Invalid relay role", { status: 400 });
  }

  const slot = url.searchParams.get("slot");
  if (role === "agent" && (slot === null || !AGENT_SLOT.test(slot))) {
    return new Response("Invalid agent relay slot", { status: 400 });
  }
  if (role === "client" && slot !== null) {
    return new Response("Clients must not specify a relay slot", { status: 400 });
  }

  const admission = await enforceRelayRequestRateLimit(request, env, "stream");
  if (!admission.ok) {
    return rateLimitResponse(admission);
  }

  const authorization = await authorizeStream(request, env, {
    deviceId,
    role,
    slot: role === "agent" ? Number.parseInt(slot, 10) : null,
  });
  if (!authorization.ok) {
    return new Response(authorization.message, { status: authorization.status });
  }

  const authenticatedDeviceIDs = verifiedDeviceIDs(authorization);
  if (authenticatedDeviceIDs.length === 0) {
    return new Response("Relay admission unavailable", { status: 503 });
  }
  for (const authenticatedDeviceID of authenticatedDeviceIDs) {
    let revoked;
    try {
      revoked = await isGlobalDeviceRevoked(env.RELAY_RATE_LIMIT, authenticatedDeviceID);
    } catch {
      return new Response("Device revocation registry unavailable", { status: 503 });
    }
    if (revoked) {
      return new Response("Device revoked", { status: 403 });
    }
    const deviceAdmission = await enforceRelayDeviceRateLimit(env, authenticatedDeviceID, "stream");
    if (!deviceAdmission.ok) {
      return rateLimitResponse(deviceAdmission);
    }
  }

  const objectId = env.DEVICE_RELAY.idFromName(deviceId);
  const forwardedRequest = role === "agent"
    ? prepareAgentRelayRequest(
        request,
        authorization.agentAdmissionReplay,
        authorization.relayTicketReplay ?? null,
        AGENT_ADMISSION_HEADER,
        CONNECTION_GRANT_HEADER,
        authorization.legacy === true,
      )
    : prepareDeviceRelayRequest(
        request,
        authorization.replay,
        CONNECTION_GRANT_HEADER,
        authorization.deviceID,
      );
  return env.DEVICE_RELAY.get(objectId).fetch(forwardedRequest);
}

async function handleDeviceGeneration(request, env, url) {
  if (request.method !== "POST" || request.body !== null) return new Response("Invalid device generation request", { status: 400 });
  const deviceID = decodeURIComponent(url.pathname.slice(DEVICE_GENERATION_PREFIX.length));
  const generationText = url.searchParams.get("generation") ?? "";
  const authorizationGeneration = /^[1-9][0-9]{0,15}$/.test(generationText) ? Number(generationText) : 0;
  if (!DEVICE_ID.test(deviceID) || !Number.isSafeInteger(authorizationGeneration) || authorizationGeneration < 1) {
    return new Response("Invalid device generation scope", { status: 400 });
  }
  const expected = typeof env.RELAY_REVOCATION_TOKEN === "string" ? env.RELAY_REVOCATION_TOKEN : "";
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(expected)) return new Response("Relay generation authority is not configured", { status: 503 });
  if (!constantTimeStringEqual(bearerToken(request), expected)) return new Response("Unauthorized", { status: 401 });
  try {
    const registered = await registerGlobalDeviceAuthorizationGeneration(env.RELAY_RATE_LIMIT, deviceID, authorizationGeneration);
    return new Response(null, { status: registered ? 204 : 409 });
  } catch {
    return new Response("Global device generation registry unavailable", { status: 503 });
  }
}

async function handleDeviceRevocation(request, env, url) {
  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }
  if (request.body !== null) {
    return new Response("Revocation request body is not allowed", { status: 400 });
  }
  const deviceID = decodeURIComponent(url.pathname.slice(DEVICE_REVOCATION_PREFIX.length));
  const generationText = url.searchParams.get("generation") ?? "";
  const authorizationGeneration = /^[1-9][0-9]{0,15}$/.test(generationText) ? Number(generationText) : 0;
  if (!DEVICE_ID.test(deviceID) || !Number.isSafeInteger(authorizationGeneration) || authorizationGeneration < 1) {
    return new Response("Invalid device revocation scope", { status: 400 });
  }
  const expected = typeof env.RELAY_REVOCATION_TOKEN === "string" ? env.RELAY_REVOCATION_TOKEN : "";
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(expected)) {
    return new Response("Relay revocation authority is not configured", { status: 503 });
  }
  if (!constantTimeStringEqual(bearerToken(request), expected)) {
    return new Response("Unauthorized", { status: 401 });
  }

  try {
    await markGlobalDeviceRevoked(env.RELAY_RATE_LIMIT, deviceID, authorizationGeneration);
  } catch {
    return new Response("Global device revocation registry unavailable", { status: 503 });
  }

  let targets;
  try {
    targets = await findAgentRevocationTargets(env.RELAY_RATE_LIMIT, deviceID);
  } catch {
    return new Response("Relay revocation registry unavailable", { status: 503 });
  }

  let failed = false;
  for (let offset = 0; offset < targets.length; offset += 32) {
    const batch = targets.slice(offset, offset + 32);
    const results = await Promise.all(batch.map(async (targetDeviceID) => {
      try {
        const objectId = env.DEVICE_RELAY.idFromName(targetDeviceID);
        const response = await env.DEVICE_RELAY.get(objectId).fetch(new Request(
          "https://wedecent.internal/revoke-device",
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ device_id: deviceID, authorization_generation: authorizationGeneration }),
          },
        ));
        return response.status === 204;
      } catch {
        return false;
      }
    }));
    if (results.some((closed) => !closed)) failed = true;
  }
  if (failed) {
    return new Response("One or more relay sessions could not be revoked", { status: 503 });
  }
  try {
    await completeGlobalDeviceRevocation(env.RELAY_RATE_LIMIT, deviceID, authorizationGeneration);
  } catch {
    return new Response("Relay revocation retry state could not be completed", { status: 503 });
  }
  return Response.json(
    { revoked_device_id: deviceID, affected_relay_devices: targets.length },
    { headers: { "Cache-Control": "no-store" } },
  );
}

function constantTimeStringEqual(left, right) {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index++) {
    difference |= a[index] ^ b[index];
  }
  return difference === 0;
}

async function authorizeDirectRequest(request, env, targetDeviceID) {
  const body = await readBoundedRequestBody(request, 1024);
  if (!body.ok) {
    return new Response("Invalid authorization request", { status: body.status });
  }

  let payload;
  try {
    payload = JSON.parse(body.text);
  } catch {
    return new Response("Invalid authorization request", { status: 400 });
  }
  const clientDeviceID = typeof payload?.client_device_id === "string" ? payload.client_device_id : "";
  if (!DEVICE_ID.test(clientDeviceID)) {
    return new Response("Invalid client device ID", { status: 400 });
  }

  const authorization = await authorizeStream(request, env, {
    deviceId: targetDeviceID,
    role: "authorize",
    slot: null,
    clientDeviceID,
  });
  if (!authorization.ok) {
    return new Response(authorization.message, { status: authorization.status });
  }

  const authenticatedDeviceIDs = verifiedDeviceIDs(authorization);
  if (authenticatedDeviceIDs.length === 0) {
    return new Response("Relay admission unavailable", { status: 503 });
  }
  for (const authenticatedDeviceID of authenticatedDeviceIDs) {
    const deviceAdmission = await enforceRelayDeviceRateLimit(env, authenticatedDeviceID, "direct");
    if (!deviceAdmission.ok) {
      return rateLimitResponse(deviceAdmission);
    }
  }

  const headers = new Headers();
  headers.set(INTERNAL_GRANT_JTI_HEADER, authorization.replay.jti);
  headers.set(INTERNAL_GRANT_EXP_HEADER, String(authorization.replay.exp));
  const objectId = env.DEVICE_RELAY.idFromName(targetDeviceID);
  return env.DEVICE_RELAY.get(objectId).fetch(
    new Request("https://wedecent.internal/authorize", { method: "POST", headers }),
  );
}

function verifiedDeviceIDs(authorization) {
  return [...new Set([authorization.deviceID, authorization.targetDeviceID].filter((value) => typeof value === "string"))];
}

function rateLimitResponse(admission) {
  return new Response(admission.message, {
    status: admission.status,
    headers: {
      "Cache-Control": "no-store",
      "Retry-After": String(admission.retryAfterSeconds),
    },
  });
}

function legacyAuthorized(request, env) {
  const token = bearerToken(request);
  return Boolean(env.RELAY_ACCESS_TOKEN) && token === env.RELAY_ACCESS_TOKEN;
}

function bearerToken(request) {
  const value = request.headers.get("Authorization");
  if (!value) {
    return "";
  }
  const match = /^Bearer ([^\s]+)$/.exec(value);
  return match ? match[1] : "";
}

export class ConnectionRateLimiter extends DurableObject {
  async fetch(request) {
    if (healthProbeRequest(request)) {
      try {
        this.ctx.storage.kv.get("__health__");
        return new Response(null, { status: 204 });
      } catch {
        return new Response("Rate-limit storage unavailable", { status: 500 });
      }
    }

    const leaseConfig = await agentConnectionLeaseRequestConfig(request);
    if (leaseConfig) {
      try {
        if (leaseConfig.action === "acquire") {
          const result = acquireGlobalAgentConnectionLease(this.ctx.storage.kv, leaseConfig);
          await this.#ensureCleanupScheduled();
          return Response.json(result, { headers: { "Cache-Control": "no-store" } });
        }
        if (leaseConfig.action === "release") {
          const released = releaseGlobalAgentConnectionLease(this.ctx.storage.kv, leaseConfig.leaseID);
          return Response.json({ released }, { headers: { "Cache-Control": "no-store" } });
        }
        if (leaseConfig.action === "bind") {
          const bound = bindGlobalAgentClientLease(this.ctx.storage.kv, leaseConfig.leaseID, leaseConfig.clientDeviceID);
          return Response.json({ bound }, { headers: { "Cache-Control": "no-store" } });
        }
        if (leaseConfig.action === "unbind") {
          const unbound = unbindGlobalAgentClientLease(this.ctx.storage.kv, leaseConfig.leaseID, leaseConfig.clientDeviceID);
          return Response.json({ unbound }, { headers: { "Cache-Control": "no-store" } });
        }
        if (leaseConfig.action === "targets") {
          const targetDeviceIDs = agentRevocationTargets(this.ctx.storage.kv, leaseConfig.deviceID);
          return Response.json({ target_device_ids: targetDeviceIDs }, { headers: { "Cache-Control": "no-store" } });
        }
        if (leaseConfig.action === "revoke-device") {
          const revoked = markGlobalDeviceRevokedLease(this.ctx.storage.kv, leaseConfig.deviceID, leaseConfig.authorizationGeneration);
          queueDeviceRevocationLease(this.ctx.storage.kv, leaseConfig.deviceID, leaseConfig.authorizationGeneration);
          await this.#ensureCleanupScheduled();
          return Response.json({ revoked }, { headers: { "Cache-Control": "no-store" } });
        }
        if (leaseConfig.action === "complete-device-revocation") {
          const completed = completeDeviceRevocationLease(this.ctx.storage.kv, leaseConfig.deviceID, leaseConfig.authorizationGeneration);
          return Response.json({ completed }, { headers: { "Cache-Control": "no-store" } });
        }
        if (leaseConfig.action === "register-generation") {
          const registered = registerGlobalDeviceAuthorizationGenerationLease(this.ctx.storage.kv, leaseConfig.deviceID, leaseConfig.authorizationGeneration);
          return Response.json({ registered }, { headers: { "Cache-Control": "no-store" } });
        }
        if (leaseConfig.action === "check-generation") {
          const current = isGlobalDeviceAuthorizationGenerationCurrentLease(this.ctx.storage.kv, leaseConfig.deviceID, leaseConfig.authorizationGeneration);
          return Response.json({ current }, { headers: { "Cache-Control": "no-store" } });
        }
        if (leaseConfig.action === "check-device") {
          const revoked = isGlobalDeviceRevokedLease(this.ctx.storage.kv, leaseConfig.deviceID);
          return Response.json({ revoked }, { headers: { "Cache-Control": "no-store" } });
        }
        return new Response("Invalid global agent lease operation", { status: 400 });
      } catch {
        return new Response("Global agent connection limiter unavailable", { status: 503 });
      }
    }

    if (new URL(request.url).pathname === "/tick" && request.method === "POST") {
      await this.alarm();
      await this.#ensureCleanupScheduled();
      return new Response(null, { status: 204 });
    }

    const config = await limiterRequestConfig(request);
    if (!config) {
      return new Response("Invalid rate-limit request", { status: 400 });
    }

    try {
      // Keep the synchronous KV read/modify/write sequence in one event-loop turn.
      const result = consumeRateLimitBuckets(this.ctx.storage.kv, config.buckets, config.windowMS, Date.now());
      await this.#ensureCleanupScheduled();
      return Response.json(
        { accepted: result.accepted, retry_after_ms: result.retryAfterMS, scope: result.scope },
        { headers: { "Cache-Control": "no-store" } },
      );
    } catch {
      return new Response("Rate-limit storage unavailable", { status: 503 });
    }
  }

  async #ensureCleanupScheduled() {
    const currentAlarm = await this.ctx.storage.getAlarm();
    if (currentAlarm === null) {
      await this.ctx.storage.setAlarm(Date.now() + RATE_LIMIT_CLEANUP_INTERVAL_MS);
    }
  }

  async alarm() {
    const nowMS = Date.now();
    const cleanup = cleanupExpiredRateLimitBuckets(this.ctx.storage.kv, nowMS);
    const leases = cleanupGlobalAgentConnectionLeases(this.ctx.storage.kv, nowMS);
    const revokedDevices = cleanupExpiredDeviceRevocationMarkers(this.ctx.storage.kv, nowMS);
    let pendingRevocations = { remaining: 0 };
    try {
      pendingRevocations = await retryPendingDeviceRevocations(
        this.env.DEVICE_RELAY,
        this.ctx.storage.kv,
        nowMS,
      );
    } catch {
      pendingRevocations = { remaining: 1 };
    }
    if (
      cleanup.remaining > 0 ||
      leases.remaining > 0 ||
      revokedDevices.remaining > 0 ||
      pendingRevocations.remaining > 0
    ) {
      await this.ctx.storage.setAlarm(nowMS + RATE_LIMIT_CLEANUP_INTERVAL_MS);
    }
  }
}

export class DeviceRelay extends DurableObject {
  #admission = Promise.resolve();

  constructor(ctx, env) {
    super(ctx, env);
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (healthProbeRequest(request)) {
      try {
        await this.ctx.storage.get("__health__");
        this.ctx.getWebSockets();
        return new Response(null, { status: 204 });
      } catch {
        return new Response("Relay storage unavailable", { status: 500 });
      }
    }
    await this.#expireAgentSessions();
    if (url.pathname === "/revoke-device") {
      return this.#revokeDevice(request);
    }
    if (url.pathname === "/status") {
      return this.#status();
    }
    if (url.pathname === "/authorize") {
      return this.#authorizeDirect(request);
    }

    const role = url.searchParams.get("role");
    if (role === "agent") {
      return this.#acceptAgent(request, url);
    }
    if (role === "client") {
      return this.#acceptClient(request);
    }
    return new Response("Invalid relay role", { status: 400 });
  }

  async #authorizeDirect(request) {
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }
    const replay = replayMetadataFromRequest(request);
    if (!replay) {
      return new Response("Connection grant replay metadata missing", { status: 403 });
    }
    const consumption = await consumeConnectionGrant(this.ctx.storage, replay.jti, replay.exp);
    if (!consumption.accepted) {
      return new Response("Connection grant already used", { status: 409 });
    }
    await scheduleReplayCleanup(this.ctx.storage, consumption.expiresAtMS);
    return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  }

  #acceptAgent(request, url) {
    return this.#withAdmission(() => this.#acceptAgentExclusive(request, url));
  }

  async #acceptAgentExclusive(request, url) {
    const slotParam = url.searchParams.get("slot");
    if (slotParam === null || !AGENT_SLOT.test(slotParam)) {
      return new Response("Invalid agent relay slot", { status: 400 });
    }
    const slot = Number.parseInt(slotParam, 10);
    const entries = this.ctx.getWebSockets("agent").map((socket) => {
      let attachment = null;
      try {
        attachment = socket.deserializeAttachment();
      } catch {
        // An unreadable attachment still counts against the active socket cap.
      }
      return { socket, readyState: socket.readyState, attachment };
    });
    const plan = planAgentSlotAdmission(entries, slot);
    if (!plan.ok) {
      return new Response(
        plan.status === 409 ? "Agent relay slot already active" : "Agent connection capacity reached",
        { status: plan.status },
      );
    }

    const admission = agentAdmissionReplayMetadataFromRequest(request);
    const relayTicket = relayTicketReplayMetadataFromRequest(request);
    const legacy = request.headers.get(INTERNAL_AGENT_LEGACY_HEADER) === "1";
    if (!admission || (legacy ? relayTicket !== null : relayTicket === null)) {
      return new Response("Agent admission replay metadata missing", { status: 403 });
    }

    const deviceID = decodeURIComponent(url.pathname.slice(STREAM_PREFIX.length));
    const leaseID = crypto.randomUUID();
    const absoluteExpiresAtMS = Date.now() + MAX_AGENT_SESSION_LIFETIME_MS;
    let globalLease;
    try {
      globalLease = await reserveGlobalAgentConnection(this.env.RELAY_RATE_LIMIT, {
        leaseID,
        deviceID,
        slot,
        expiresAtMS: absoluteExpiresAtMS,
        authorizationGeneration: admission.authorizationGeneration,
      });
    } catch {
      return new Response("Global agent connection limiter unavailable", { status: 503 });
    }
    if (globalLease.revoked || globalLease.generationMismatch) {
      return new Response("Agent authorization generation is stale or revoked", { status: 403 });
    }
    if (!globalLease.accepted) {
      return new Response("Global agent connection capacity reached", { status: 429, headers: { "Retry-After": "1" } });
    }

    let leaseOwned = true;
    try {
      const consumption = await consumeAgentAdmission(
        this.ctx.storage,
        admission.jti,
        admission.exp,
        relayTicket?.jti ?? null,
        relayTicket?.exp ?? null,
      );
      if (!consumption.accepted) {
        return new Response("Agent admission already used or expired", { status: 409 });
      }
      await scheduleReplayCleanup(this.ctx.storage, consumption.expiresAtMS);

      // Only replace free sockets after the new admission capability has been consumed.
      for (const entry of plan.retire) {
        entry.socket.close(1000, "Superseded relay slot");
      }

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      const id = crypto.randomUUID();
      server.serializeAttachment(createAgentSessionAttachment({
        id,
        role: "agent",
        peerId: null,
        deviceID,
        clientDeviceID: null,
        slot,
        leaseID,
        absoluteExpiresAtMS,
        authorizationGeneration: admission.authorizationGeneration,
      }));
      this.ctx.acceptWebSocket(server, ["agent", `agent-slot-${slot}`]);
      leaseOwned = false;
      let revokedAfterAccept;
      try {
        const generationCurrent = await isGlobalDeviceAuthorizationGenerationCurrent(
          this.env.RELAY_RATE_LIMIT, deviceID, admission.authorizationGeneration,
        );
        revokedAfterAccept = !generationCurrent || await isGlobalDeviceRevoked(this.env.RELAY_RATE_LIMIT, deviceID);
      } catch {
        server.close(1011, "Device revocation registry unavailable");
        return new Response("Device revocation registry unavailable", { status: 503 });
      }
      if (revokedAfterAccept) {
        server.close(4003, "Device revoked");
      }
      try {
        await this.#scheduleAgentSessionAlarm();
      } catch {
        server.close(1011, "Relay session expiry could not be scheduled");
        return new Response("Relay session expiry could not be scheduled", { status: 503 });
      }

      return new Response(null, { status: 101, webSocket: client });
    } finally {
      if (leaseOwned) {
        await this.#releaseAgentLease(leaseID);
      }
    }
  }

  #acceptClient(request) {
    return this.#withAdmission(() => this.#acceptClientExclusive(request));
  }

  #withAdmission(operation) {
    let release;
    const previous = this.#admission;
    this.#admission = new Promise((resolve) => {
      release = resolve;
    });
    return previous.then(operation).finally(() => release());
  }

  async #acceptClientExclusive(request) {
    const clientDeviceID = request.headers.get(INTERNAL_CLIENT_DEVICE_ID_HEADER)?.trim() ?? "";
    if (!DEVICE_ID.test(clientDeviceID)) {
      return new Response("Authenticated client device identity missing", { status: 403 });
    }

    const agent = this.ctx.getWebSockets("agent").find((socket) => {
      if (socket.readyState !== WebSocket.OPEN) {
        return false;
      }
      const attachment = socket.deserializeAttachment();
      return (
        attachment?.role === "agent" &&
        !attachment.peerId &&
        DEVICE_ID.test(attachment.deviceID ?? "") &&
        AGENT_LEASE_ID.test(attachment.leaseID ?? "")
      );
    });

    if (!agent) {
      return new Response("No agent relay slot is currently available", {
        status: 503,
        headers: { "Retry-After": "1" },
      });
    }

    const replay = replayMetadataFromRequest(request);
    if (!replay) {
      return new Response("Connection grant replay metadata missing", { status: 403 });
    }

    const consumption = await consumeConnectionGrant(this.ctx.storage, replay.jti, replay.exp);
    if (!consumption.accepted) {
      return new Response("Connection grant already used", { status: 409 });
    }
    await scheduleReplayCleanup(this.ctx.storage, consumption.expiresAtMS);

    const agentAttachment = agent.deserializeAttachment();
    const touchedAgentAttachment = touchAgentSessionAttachment(agentAttachment, Date.now());
    if (!touchedAgentAttachment) {
      agent.close(4001, "Relay session expired");
      return new Response("Agent relay session expired", { status: 503, headers: { "Retry-After": "1" } });
    }

    let bound = false;
    try {
      bound = await bindGlobalAgentClient(this.env.RELAY_RATE_LIMIT, agentAttachment.leaseID, clientDeviceID);
      if (!bound) {
        const revokedClient = await isGlobalDeviceRevoked(this.env.RELAY_RATE_LIMIT, clientDeviceID);
        const revokedAgent = await isGlobalDeviceRevoked(this.env.RELAY_RATE_LIMIT, agentAttachment.deviceID);
        if (revokedClient || revokedAgent) {
          return new Response("Device revoked", { status: 403 });
        }
        return new Response("Agent relay session is no longer registered", { status: 503, headers: { "Retry-After": "1" } });
      }

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      const clientId = crypto.randomUUID();
      server.serializeAttachment({
        id: clientId,
        role: "client",
        peerId: agentAttachment.id,
        clientDeviceID,
        targetDeviceID: agentAttachment.deviceID,
        leaseID: agentAttachment.leaseID,
      });
      this.ctx.acceptWebSocket(server, ["client"]);
      try {
        agent.serializeAttachment({
          ...touchedAgentAttachment,
          peerId: clientId,
          clientDeviceID,
        });
      } catch (error) {
        server.close(1011, "Unable to attach relay peer");
        throw error;
      }
      bound = false;
      let revokedAfterAccept;
      try {
        const agentGenerationCurrent = await isGlobalDeviceAuthorizationGenerationCurrent(
          this.env.RELAY_RATE_LIMIT, agentAttachment.deviceID, agentAttachment.authorizationGeneration,
        );
        revokedAfterAccept =
          !agentGenerationCurrent ||
          await isGlobalDeviceRevoked(this.env.RELAY_RATE_LIMIT, clientDeviceID) ||
          await isGlobalDeviceRevoked(this.env.RELAY_RATE_LIMIT, agentAttachment.deviceID);
      } catch {
        server.close(1011, "Device revocation registry unavailable");
        agent.close(1011, "Device revocation registry unavailable");
        return new Response("Device revocation registry unavailable", { status: 503 });
      }
      if (revokedAfterAccept) {
        server.close(4003, "Device revoked");
        agent.close(4003, "Device revoked");
      }
      try {
        await this.#scheduleAgentSessionAlarm();
      } catch {
        server.close(1011, "Relay session expiry could not be scheduled");
        agent.close(1011, "Relay session expiry could not be scheduled");
        return new Response("Relay session expiry could not be scheduled", { status: 503 });
      }
      return new Response(null, { status: 101, webSocket: client });
    } finally {
      if (bound) {
        try {
          await unbindGlobalAgentClient(this.env.RELAY_RATE_LIMIT, agentAttachment.leaseID, clientDeviceID);
        } catch {
          // The absolute agent lease still bounds stale client identity state.
        }
      }
    }
  }

  async #revokeDevice(request) {
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }
    const body = await readBoundedRequestBody(request, 1024);
    if (!body.ok) {
      return new Response("Invalid device revocation event", { status: body.status });
    }
    let payload;
    try {
      payload = JSON.parse(body.text);
    } catch {
      return new Response("Invalid device revocation event", { status: 400 });
    }
    if (
      payload === null ||
      typeof payload !== "object" ||
      Array.isArray(payload) ||
      Object.keys(payload).length !== 2 ||
      typeof payload.device_id !== "string" ||
      !DEVICE_ID.test(payload.device_id) ||
      !Number.isSafeInteger(payload.authorization_generation) ||
      payload.authorization_generation < 1
    ) {
      return new Response("Invalid device revocation event", { status: 400 });
    }

    const revokedDeviceID = payload.device_id;
    for (const socket of this.ctx.getWebSockets()) {
      let attachment;
      try {
        attachment = socket.deserializeAttachment();
      } catch {
        socket.close(1011, "Invalid relay session state");
        continue;
      }
      const affected = attachment?.role === "agent"
        ? attachment.deviceID === revokedDeviceID || attachment.clientDeviceID === revokedDeviceID
        : attachment?.role === "client"
          ? attachment.clientDeviceID === revokedDeviceID || attachment.targetDeviceID === revokedDeviceID
          : true;
      if (!affected || socket.readyState !== WebSocket.OPEN) continue;
      const peer = attachment?.peerId ? this.#findSocket(attachment.peerId) : null;
      socket.close(4003, "Device revoked");
      if (peer && peer.readyState === WebSocket.OPEN) {
        peer.close(4003, "Device revoked");
      }
    }
    return new Response(null, { status: 204 });
  }

  async alarm() {
    await cleanupExpiredConnectionGrants(this.ctx.storage);
    await this.#expireAgentSessions();
  }

  async #expireAgentSessions() {
    const nowMS = Date.now();
    for (const socket of this.ctx.getWebSockets("agent")) {
      let attachment;
      try {
        attachment = socket.deserializeAttachment();
      } catch {
        socket.close(1011, "Invalid relay session state");
        continue;
      }
      if (
        DEVICE_ID.test(attachment?.deviceID ?? "") &&
        AGENT_LEASE_ID.test(attachment?.leaseID ?? "") &&
        !agentSessionExpired(attachment, nowMS)
      ) continue;
      const peer = attachment?.peerId ? this.#findSocket(attachment.peerId) : null;
      socket.close(4001, "Relay session expired");
      if (peer && peer.readyState === WebSocket.OPEN) {
        peer.close(4001, "Relay session expired");
      }
    }
    await this.#scheduleAgentSessionAlarm(nowMS);
  }

  async #releaseAgentLease(leaseID) {
    try {
      await releaseGlobalAgentConnection(this.env.RELAY_RATE_LIMIT, leaseID);
    } catch {
      // Expiring the bounded lease is the fail-safe if explicit release is unavailable.
    }
  }

  async #scheduleAgentSessionAlarm(nowMS = Date.now()) {
    const entries = this.ctx.getWebSockets("agent").map((socket) => {
      try {
        return { readyState: socket.readyState, attachment: socket.deserializeAttachment() };
      } catch {
        return { readyState: socket.readyState, attachment: null };
      }
    });
    const nextExpiryMS = nextAgentSessionExpiry(entries, nowMS);
    if (nextExpiryMS === null) return;
    const currentAlarm = await this.ctx.storage.getAlarm();
    const scheduledAtMS = Math.max(nowMS + 1, nextExpiryMS);
    if (currentAlarm === null || scheduledAtMS < currentAlarm) {
      await this.ctx.storage.setAlarm(scheduledAtMS);
    }
  }

  #status() {
    const agents = this.ctx.getWebSockets("agent");
    const clients = this.ctx.getWebSockets("client");
    let freeAgents = 0;
    let openAgents = 0;

    for (const socket of agents) {
      if (socket.readyState !== WebSocket.OPEN) {
        continue;
      }
      openAgents++;
      const attachment = socket.deserializeAttachment();
      if (attachment?.role === "agent" && !attachment.peerId) {
        freeAgents++;
      }
    }

    return Response.json({
      agents: agents.length,
      openAgents,
      freeAgents,
      clients: clients.length,
    });
  }

  webSocketMessage(socket, message) {
    const attachment = socket.deserializeAttachment();
    if (!attachment?.peerId) {
      socket.close(1011, "Relay peer is not attached");
      return;
    }

    const peer = this.#findSocket(attachment.peerId);
    if (!peer || peer.readyState !== WebSocket.OPEN) {
      socket.close(1011, "Relay peer disconnected");
      return;
    }

    const agentSocket = attachment.role === "agent" ? socket : peer;
    let agentAttachment;
    try {
      agentAttachment = agentSocket.deserializeAttachment();
    } catch {
      socket.close(1011, "Invalid relay session state");
      peer.close(1011, "Invalid relay session state");
      return;
    }
    if (
      !DEVICE_ID.test(agentAttachment?.deviceID ?? "") ||
      !AGENT_LEASE_ID.test(agentAttachment?.leaseID ?? "")
    ) {
      socket.close(1011, "Relay session identity is invalid");
      peer.close(1011, "Relay session identity is invalid");
      return;
    }
    const touched = touchAgentSessionAttachment(agentAttachment, Date.now());
    if (!touched) {
      socket.close(4001, "Relay session expired");
      peer.close(4001, "Relay session expired");
      return;
    }
    agentSocket.serializeAttachment(touched);
    peer.send(message);
  }

  async webSocketClose(socket, code, reason) {
    const attachment = socket.deserializeAttachment();
    if (attachment?.role === "agent" && typeof attachment.leaseID === "string") {
      await this.#releaseAgentLease(attachment.leaseID);
    } else if (
      attachment?.role === "client" &&
      AGENT_LEASE_ID.test(attachment.leaseID ?? "") &&
      DEVICE_ID.test(attachment.clientDeviceID ?? "")
    ) {
      try {
        await unbindGlobalAgentClient(this.env.RELAY_RATE_LIMIT, attachment.leaseID, attachment.clientDeviceID);
      } catch {
        // Agent lease expiry removes stale client-device bindings.
      }
    }
    if (!attachment?.peerId) {
      return;
    }

    const peer = this.#findSocket(attachment.peerId);
    if (peer && peer.readyState === WebSocket.OPEN) {
      const peerCode = code === 1000 ? 1000 : code === 4003 ? 4003 : 1011;
      peer.close(peerCode, reason || "Relay peer disconnected");
    }
  }

  async webSocketError(socket) {
    const attachment = socket.deserializeAttachment();
    if (attachment?.role === "agent" && typeof attachment.leaseID === "string") {
      await this.#releaseAgentLease(attachment.leaseID);
    } else if (
      attachment?.role === "client" &&
      AGENT_LEASE_ID.test(attachment.leaseID ?? "") &&
      DEVICE_ID.test(attachment.clientDeviceID ?? "")
    ) {
      try {
        await unbindGlobalAgentClient(this.env.RELAY_RATE_LIMIT, attachment.leaseID, attachment.clientDeviceID);
      } catch {
        // Agent lease expiry removes stale client-device bindings.
      }
    }
    if (!attachment?.peerId) {
      return;
    }

    const peer = this.#findSocket(attachment.peerId);
    if (peer && peer.readyState === WebSocket.OPEN) {
      peer.close(1011, "Relay peer error");
    }
  }

  #findSocket(id) {
    for (const socket of this.ctx.getWebSockets()) {
      try {
        if (socket.deserializeAttachment()?.id === id) return socket;
      } catch {
        // Malformed peer state is not a match.
      }
    }
    return null;
  }
}
