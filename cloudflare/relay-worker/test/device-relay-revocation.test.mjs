import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
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

const { default: worker, DeviceRelay } = await import("../src/index.js");
const { deviceIDFromPublicKey } = await import("../src/relay-auth.js");

const encoder = new TextEncoder();
const signingContext = "wedecent-relay-ticket-v2\n";

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}

async function issueRelayTicket({ keys, role, targetDeviceID, slot = null }) {
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const issuer = await deviceIDFromPublicKey(publicKey);
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    v: 2,
    aud: "wedecent-relay",
    iss: issuer,
    sub: role === "agent" ? issuer : targetDeviceID,
    role,
    ...(role === "agent" ? { slot } : {}),
    iat: now,
    exp: now + 90,
    jti: b64url(crypto.getRandomValues(new Uint8Array(16))),
    pk: b64url(publicKey),
  };
  const payload = b64url(encoder.encode(JSON.stringify(claims)));
  const signature = await crypto.subtle.sign(
    "Ed25519",
    keys.privateKey,
    encoder.encode(signingContext + payload),
  );
  return { token: `wdt2.${payload}.${b64url(new Uint8Array(signature))}`, deviceID: issuer };
}

function issueConnectionGrant({ clientDeviceID, targetDeviceID, signingKey, kid }) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "EdDSA", typ: "JWT", kid };
  const claims = {
    grant_id: randomUUID(),
    organization_id: null,
    client_device_id: clientDeviceID,
    target_device_id: targetDeviceID,
    permission: "terminal.connect",
    iss: "wedecent-control-plane",
    aud: "wedecent-relay",
    sub: "0b7729e9-95bf-4591-80f4-3f0616e57751",
    jti: randomUUID(),
    iat: now,
    exp: now + 90,
  };
  const input = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(Buffer.from(JSON.stringify(claims)))}`;
  return `${input}.${b64url(sign(null, Buffer.from(input), signingKey))}`;
}

function workerRequest(deviceID, role, token, slot = null, grant = null) {
  const url = new URL(`https://relay.wedecent.test/v1/stream/${deviceID}`);
  url.searchParams.set("role", role);
  if (slot !== null) url.searchParams.set("slot", String(slot));
  const headers = {
    Upgrade: "websocket",
    Authorization: `Bearer ${token}`,
    "CF-Connecting-IP": "192.0.2.44",
  };
  if (grant) headers["X-WeDecent-Connection-Grant"] = grant;
  return new Request(url, { headers });
}

test("Worker and Durable Object revoke one established relay, preserve peers, and reject replay", async () => {
  const storage = new StorageFixture();
  const acceptedSockets = [];
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
  const env = {
    DEVICE_RELAY: {
      idFromName: (deviceID) => deviceID,
      get: () => ({ fetch: (request) => relay.fetch(request) }),
    },
    RELAY_RATE_LIMIT: {
      idFromName: (bucket) => bucket,
      get: () => ({
        fetch: async () => WorkerResponse.json({ accepted: true, retry_after_ms: 0 }),
      }),
    },
  };

  const agentKeys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const agentIdentity = await issueRelayTicket({
    keys: agentKeys,
    role: "agent",
    targetDeviceID: "",
    slot: 1,
  });
  const targetDeviceID = agentIdentity.deviceID;
  const agentResponses = [];
  const agentSockets = [];

  for (const slot of [1, 2, 3]) {
    const ticket = slot === 1
      ? agentIdentity
      : await issueRelayTicket({ keys: agentKeys, role: "agent", targetDeviceID: "", slot });
    agentResponses.push(await worker.fetch(
      workerRequest(targetDeviceID, "agent", ticket.token, slot),
      env,
    ));
    assert.equal(agentResponses.at(-1).status, 101);
    agentSockets.push(acceptedSockets.at(-1));
  }

  const controlPlaneKeys = generateKeyPairSync("ed25519");
  const publicSPKIB64 = controlPlaneKeys.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const publicJWK = controlPlaneKeys.publicKey.export({ format: "jwk" });
  const kid = b64url(createHash("sha256").update(
    JSON.stringify({ crv: "Ed25519", kty: "OKP", x: publicJWK.x }),
  ).digest());
  env.WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64 = publicSPKIB64;

  const clientAKeys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const clientBKeys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const clientAIdentity = await issueRelayTicket({ keys: clientAKeys, role: "client", targetDeviceID });
  const clientBIdentity = await issueRelayTicket({ keys: clientBKeys, role: "client", targetDeviceID });
  const grantA = issueConnectionGrant({
    clientDeviceID: clientAIdentity.deviceID,
    targetDeviceID,
    signingKey: controlPlaneKeys.privateKey,
    kid,
  });
  const grantB = issueConnectionGrant({
    clientDeviceID: clientBIdentity.deviceID,
    targetDeviceID,
    signingKey: controlPlaneKeys.privateKey,
    kid,
  });

  const clientAResponse = await worker.fetch(
    workerRequest(targetDeviceID, "client", clientAIdentity.token, null, grantA),
    env,
  );
  assert.equal(clientAResponse.status, 101);
  const clientASocket = acceptedSockets.find((socket) =>
    socket.deserializeAttachment()?.role === "client" &&
    socket.deserializeAttachment()?.peerId === agentSockets[0].deserializeAttachment()?.id
  );

  const clientBResponse = await worker.fetch(
    workerRequest(targetDeviceID, "client", clientBIdentity.token, null, grantB),
    env,
  );
  assert.equal(clientBResponse.status, 101);
  const clientBSocket = acceptedSockets.find((socket) =>
    socket.deserializeAttachment()?.role === "client" &&
    socket.deserializeAttachment()?.peerId === agentSockets[1].deserializeAttachment()?.id
  );

  assert.ok(clientASocket);
  assert.ok(clientBSocket);
  assert.equal(agentSockets[0].deserializeAttachment().peerId, clientASocket.deserializeAttachment().id);
  assert.equal(agentSockets[1].deserializeAttachment().peerId, clientBSocket.deserializeAttachment().id);

  const replayed = await worker.fetch(
    workerRequest(targetDeviceID, "client", clientAIdentity.token, null, grantA),
    env,
  );
  assert.equal(replayed.status, 409);
  assert.equal(await replayed.text(), "Connection grant already used");
  assert.equal(agentSockets[2].deserializeAttachment().peerId, null);

  // The agent's TLS transport has been force-closed by local session revocation.
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
