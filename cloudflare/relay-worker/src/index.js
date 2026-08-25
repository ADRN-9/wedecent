import { DurableObject } from "cloudflare:workers";

const DEVICE_ID = /^wd_[a-z2-7]{16}$/;
const STREAM_PREFIX = "/v1/stream/";
const STATUS_PREFIX = "/v1/status/";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/healthz") {
      return Response.json({ service: "wedecent-relay", status: "ok", version: 3 });
    }

    if (!url.pathname.startsWith(STREAM_PREFIX) && !url.pathname.startsWith(STATUS_PREFIX)) {
      return new Response("Not found", { status: 404 });
    }

    if (!env.RELAY_ACCESS_TOKEN) {
      return new Response("Relay access token is not configured", { status: 503 });
    }
    if (request.headers.get("Authorization") !== `Bearer ${env.RELAY_ACCESS_TOKEN}`) {
      return new Response("Unauthorized", { status: 401 });
    }

    if (url.pathname.startsWith(STATUS_PREFIX)) {
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

    const objectId = env.DEVICE_RELAY.idFromName(deviceId);
    return env.DEVICE_RELAY.get(objectId).fetch(request);
  },
};

export class DeviceRelay extends DurableObject {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/status") {
      return this.#status();
    }

    const role = url.searchParams.get("role");
    if (role === "agent") {
      return this.#acceptAgent();
    }
    if (role === "client") {
      return this.#acceptClient();
    }
    return new Response("Invalid relay role", { status: 400 });
  }

  #acceptAgent() {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const id = crypto.randomUUID();

    server.serializeAttachment({ id, role: "agent", peerId: null });
    this.ctx.acceptWebSocket(server, ["agent"]);

    return new Response(null, { status: 101, webSocket: client });
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
