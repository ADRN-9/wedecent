import { DurableObject } from "cloudflare:workers";
import { verifyRelayTicket } from "./relay-auth.js";

const DEVICE_ID = /^wd_[a-z2-7]{16}$/;
const STREAM_PREFIX = "/v1/stream/";
const STATUS_PREFIX = "/v1/status/";
const AGENT_SLOT = /^(?:[1-9]|[12][0-9]|3[0-2])$/;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/healthz") {
      return Response.json({ service: "wedecent-relay", status: "ok", version: 5 });
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
    if (role === "agent" && slot !== null && !AGENT_SLOT.test(slot)) {
      return new Response("Invalid agent relay slot", { status: 400 });
    }
    if (role === "client" && slot !== null) {
      return new Response("Clients must not specify a relay slot", { status: 400 });
    }

    if (!(await streamAuthorized(request, env, { deviceId, role, slot: role === "agent" ? Number.parseInt(slot, 10) : null }))) {
      return new Response("Unauthorized", { status: 401 });
    }

    const objectId = env.DEVICE_RELAY.idFromName(deviceId);
    return env.DEVICE_RELAY.get(objectId).fetch(request);
  },
};


async function streamAuthorized(request, env, expected) {
  const token = bearerToken(request);
  if (!token) {
    return false;
  }
  if (token.startsWith("wdt2.")) {
    try {
      await verifyRelayTicket(token, expected);
      return true;
    } catch {
      return false;
    }
  }
  return Boolean(env.RELAY_ACCESS_TOKEN) && token === env.RELAY_ACCESS_TOKEN;
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

export class DeviceRelay extends DurableObject {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/status") {
      return this.#status();
    }

    const role = url.searchParams.get("role");
    if (role === "agent") {
      return this.#acceptAgent(url);
    }
    if (role === "client") {
      return this.#acceptClient();
    }
    return new Response("Invalid relay role", { status: 400 });
  }

  #acceptAgent(url) {
    const slotParam = url.searchParams.get("slot");
    const slot = slotParam === null ? null : Number.parseInt(slotParam, 10);

    // v4 agents identify each parked outbound connection by a stable logical
    // slot number. Retire free sockets from older generations before accepting
    // the replacement. This prevents hibernated/stale Durable Object sockets
    // from accumulating across agent restarts and being selected by clients.
    if (slot !== null) {
      this.#retireSupersededFreeAgents(slot);
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const id = crypto.randomUUID();
    const tags = ["agent"];
    if (slot !== null) {
      tags.push(`agent-slot-${slot}`);
    }

    server.serializeAttachment({ id, role: "agent", peerId: null, slot });
    this.ctx.acceptWebSocket(server, tags);

    return new Response(null, { status: 101, webSocket: client });
  }

  #retireSupersededFreeAgents(slot) {
    for (const socket of this.ctx.getWebSockets("agent")) {
      if (socket.readyState !== WebSocket.OPEN) {
        continue;
      }

      const attachment = socket.deserializeAttachment();
      if (attachment?.role !== "agent" || attachment.peerId) {
        continue;
      }

      const legacy = !Number.isInteger(attachment.slot);
      const duplicateSlot = attachment.slot === slot;
      if (legacy || duplicateSlot) {
        socket.close(1000, legacy ? "Replaced legacy relay slot" : "Superseded relay slot");
      }
    }
  }

  #acceptClient() {
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

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const clientId = crypto.randomUUID();
    const agentAttachment = agent.deserializeAttachment();

    server.serializeAttachment({ id: clientId, role: "client", peerId: agentAttachment.id });
    agent.serializeAttachment({ ...agentAttachment, peerId: clientId });
    this.ctx.acceptWebSocket(server, ["client"]);

    return new Response(null, { status: 101, webSocket: client });
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
