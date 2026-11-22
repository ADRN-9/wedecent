import { DurableObject } from "cloudflare:workers";
import { authorizeStream, AGENT_ADMISSION_HEADER, CONNECTION_GRANT_HEADER } from "./stream-auth.js";
import {
  agentAdmissionReplayMetadataFromRequest,
  cleanupExpiredConnectionGrants,
  consumeAgentAdmission,
  consumeConnectionGrant,
  INTERNAL_AGENT_LEGACY_HEADER,
  INTERNAL_GRANT_EXP_HEADER,
  INTERNAL_GRANT_JTI_HEADER,
  prepareAgentRelayRequest,
  prepareDeviceRelayRequest,
  relayTicketReplayMetadataFromRequest,
  replayMetadataFromRequest,
  scheduleReplayCleanup,
} from "./grant-replay.js";
import { planAgentSlotAdmission } from "./agent-slots.js";
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
  cleanupExpiredRateLimitBuckets,
  consumeRateLimitBuckets,
  RATE_LIMIT_CLEANUP_INTERVAL_MS,
  enforceRelayDeviceRateLimit,
  enforceRelayRequestRateLimit,
  limiterRequestConfig,
} from "./rate-limit.js";

const DEVICE_ID = /^wd_[a-z2-7]{16}$/;
const STREAM_PREFIX = "/v1/stream/";
const STATUS_PREFIX = "/v1/status/";
const TIME_PATH = "/v1/time";
const DIRECT_AUTHORIZE_PREFIX = "/v1/direct-authorize/";
const AGENT_SLOT = /^(?:[1-9]|[12][0-9]|3[0-2])$/;
const HEALTH_VERSION = 12;

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
    : prepareDeviceRelayRequest(request, authorization.replay, CONNECTION_GRANT_HEADER);
  return env.DEVICE_RELAY.get(objectId).fetch(forwardedRequest);
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
    const cleanup = cleanupExpiredRateLimitBuckets(this.ctx.storage.kv, Date.now());
    if (cleanup.remaining > 0) {
      await this.ctx.storage.setAlarm(Date.now() + RATE_LIMIT_CLEANUP_INTERVAL_MS);
    }
  }
}

export class DeviceRelay extends DurableObject {
  #admission = Promise.resolve();

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
    server.serializeAttachment({ id, role: "agent", peerId: null, slot });
    this.ctx.acceptWebSocket(server, ["agent", `agent-slot-${slot}`]);

    return new Response(null, { status: 101, webSocket: client });
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
    const agent = this.ctx.getWebSockets("agent").find((socket) => {
      if (socket.readyState !== WebSocket.OPEN) {
        return false;
      }
      const attachment = socket.deserializeAttachment();
      return attachment?.role === "agent" && !attachment.peerId;
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

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const clientId = crypto.randomUUID();
    const agentAttachment = agent.deserializeAttachment();

    server.serializeAttachment({ id: clientId, role: "client", peerId: agentAttachment.id });
    agent.serializeAttachment({ ...agentAttachment, peerId: clientId });
    this.ctx.acceptWebSocket(server, ["client"]);

    return new Response(null, { status: 101, webSocket: client });
  }

  async alarm() {
    await cleanupExpiredConnectionGrants(this.ctx.storage);
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

    peer.send(message);
  }

  webSocketClose(socket, code, reason) {
    const attachment = socket.deserializeAttachment();
    if (!attachment?.peerId) {
      return;
    }

    const peer = this.#findSocket(attachment.peerId);
    if (peer && peer.readyState === WebSocket.OPEN) {
      peer.close(code === 1000 ? 1000 : 1011, reason || "Relay peer disconnected");
    }
  }

  webSocketError(socket) {
    const attachment = socket.deserializeAttachment();
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
      const attachment = socket.deserializeAttachment();
      if (attachment?.id === id) {
        return socket;
      }
    }
    return null;
  }
}
