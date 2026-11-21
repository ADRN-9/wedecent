import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import test from "node:test";

const workerModule = `export class DurableObject {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }
}`;
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "cloudflare:workers") {
      return {
        url: `data:text/javascript,${encodeURIComponent(workerModule)}`,
        shortCircuit: true,
      };
    }
    return nextResolve(specifier, context);
  },
});

class WorkerResponse {
  constructor(body = null, init = {}) {
    this.body = body;
    this.status = init.status ?? 200;
    this.statusText = init.statusText ?? "";
    this.headers = new Headers(init.headers);
    this.webSocket = init.webSocket;
  }

  static json(value, init = {}) {
    const headers = new Headers(init.headers);
    headers.set("Content-Type", "application/json");
    return new WorkerResponse(JSON.stringify(value), { ...init, headers });
  }

  get ok() {
    return this.status >= 200 && this.status < 300;
  }

  async text() {
    return this.body === null ? "" : String(this.body);
  }

  async json() {
    return JSON.parse(await this.text());
  }
}

class FakeSocket {
  constructor() {
    this.readyState = 1;
    this.attachment = null;
    this.tags = [];
    this.sent = [];
    this.closeInfo = null;
    this.peer = null;
  }

  serializeAttachment(value) {
    this.attachment = structuredClone(value);
  }

  deserializeAttachment() {
    return this.attachment === null ? null : structuredClone(this.attachment);
  }

  send(message) {
    if (this.readyState !== 1) throw new Error("socket is closed");
    this.sent.push(message);
  }

  close(code = 1000, reason = "") {
    if (this.readyState !== 1) return;
    this.readyState = 3;
    this.closeInfo = { code, reason };
    if (this.peer?.readyState === 1) {
      this.peer.readyState = 3;
      this.peer.closeInfo = { code, reason };
    }
  }
}

class FakeWebSocketPair {
  constructor() {
    const client = new FakeSocket();
    const server = new FakeSocket();
    client.peer = server;
    server.peer = client;
    return { 0: client, 1: server };
  }
}

class StorageFixture {
  constructor() {
    this.values = new Map();
    this.alarm = null;
    this.lock = Promise.resolve();
  }

  async transaction(callback) {
    let release;
    const previous = this.lock;
    this.lock = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      return await callback({
        get: async (key) => this.values.get(key),
        put: async (key, value) => { this.values.set(key, value); },
      });
    } finally {
      release();
    }
  }

  async get(key) {
    return this.values.get(key);
  }

  async getAlarm() {
    return this.alarm;
  }

  async setAlarm(value) {
    this.alarm = value;
  }

  async list({ prefix }) {
    return new Map([...this.values].filter(([key]) => key.startsWith(prefix)));
  }

  async delete(key) {
    this.values.delete(key);
  }
}

globalThis.Response = WorkerResponse;
globalThis.WebSocket = { OPEN: 1 };
globalThis.WebSocketPair = FakeWebSocketPair;

const { DeviceRelay } = await import("../src/index.js");
const { prepareDeviceRelayRequest } = await import("../src/grant-replay.js");

const targetDeviceID = "wd_bbbbbbbbbbbbbbbb";

function replay(jti, grantID, clientDeviceID, authorizationRunID, validationAttemptID) {
  const nowMS = Date.now();
  return {
    jti,
    exp: Math.floor(nowMS / 1000) + 90,
    grantID,
    clientDeviceID,
    targetDeviceID,
    flow: "relay",
    permission: "terminal.connect",
    validatedAtMS: nowMS,
    authorizationRunID,
    validationAttemptID,
  };
}

function makeClientRequest(grantReplay) {
  const request = new Request(
    `https://wedecent.internal/v1/stream/${targetDeviceID}?role=client`,
    { headers: { Upgrade: "websocket" } },
  );
  return prepareDeviceRelayRequest(request, grantReplay, "X-WeDecent-Connection-Grant");
}

test("established relay revocation closes only its paired client and preserves replay protection", async () => {
  const acceptedSockets = [];
  const storage = new StorageFixture();
  const ctx = {
    storage,
    acceptWebSocket(socket, tags) {
      socket.tags = [...tags];
      acceptedSockets.push(socket);
    },
    getWebSockets(tag) {
      return tag
        ? acceptedSockets.filter((socket) => socket.tags.includes(tag))
        : [...acceptedSockets];
    },
  };
  const relay = new DeviceRelay(ctx, {});

  const agentResponses = [];
  for (const slot of [1, 2, 3]) {
    agentResponses.push(await relay.fetch(new Request(
      `https://wedecent.internal/v1/stream/${targetDeviceID}?role=agent&slot=${slot}`,
      { headers: { Upgrade: "websocket" } },
    )));
    assert.equal(agentResponses.at(-1).status, 101);
  }

  const agentSockets = [...acceptedSockets];
  assert.equal(agentSockets.length, 3);

  const replayA = replay(
    "76b4c468-4e39-437c-a9c8-b758c92ab89b",
    "d90987bf-bae6-45da-ab21-c82d049617bd",
    "wd_aaaaaaaaaaaaaaaa",
    "d90987bf-bae6-45da-ab21-c82d049617bd",
    "b90987bf-bae6-45da-ab21-c82d049617bd",
  );
  const replayB = replay(
    "86b4c468-4e39-437c-a9c8-b758c92ab89b",
    "e90987bf-bae6-45da-ab21-c82d049617bd",
    "wd_cccccccccccccccc",
    "e90987bf-bae6-45da-ab21-c82d049617bd",
    "c90987bf-bae6-45da-ab21-c82d049617bd",
  );

  const clientAResponse = await relay.fetch(makeClientRequest(replayA));
  assert.equal(clientAResponse.status, 101);
  const clientASocket = acceptedSockets.find((socket) =>
    socket.deserializeAttachment()?.role === "client" &&
    socket.deserializeAttachment()?.peerId === agentSockets[0].deserializeAttachment()?.id
  );

  const clientBResponse = await relay.fetch(makeClientRequest(replayB));
  assert.equal(clientBResponse.status, 101);
  const clientBSocket = acceptedSockets.find((socket) =>
    socket.deserializeAttachment()?.role === "client" &&
    socket.deserializeAttachment()?.peerId === agentSockets[1].deserializeAttachment()?.id
  );

  assert.ok(clientASocket);
  assert.ok(clientBSocket);
  assert.equal(agentSockets[0].deserializeAttachment().peerId, clientASocket.deserializeAttachment().id);
  assert.equal(agentSockets[1].deserializeAttachment().peerId, clientBSocket.deserializeAttachment().id);

  // The third agent remains free so the replay reaches the actual DO admission path.
  const replayed = await relay.fetch(makeClientRequest(replayA));
  assert.equal(replayed.status, 409);
  assert.equal(await replayed.text(), "Connection grant already used");
  assert.equal(agentSockets[2].deserializeAttachment().peerId, null);

  // Model the agent's TLS transport being force-closed after local revocation.
  agentResponses[0].webSocket.close(1000, "Terminal session revoked");
  relay.webSocketClose(agentSockets[0], 1000, "Terminal session revoked");
  assert.equal(agentSockets[0].readyState, 3);
  assert.equal(clientASocket.readyState, 3);
  assert.equal(clientAResponse.webSocket.readyState, 3);
  assert.deepEqual(clientASocket.closeInfo, {
    code: 1000,
    reason: "Terminal session revoked",
  });

  assert.equal(agentSockets[1].readyState, 1);
  assert.equal(clientBSocket.readyState, 1);
  relay.webSocketMessage(agentSockets[1], "still-active-session");
  assert.deepEqual(clientBSocket.sent, ["still-active-session"]);
});
