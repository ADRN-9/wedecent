import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { spawn } from "node:child_process";
import { connect, createServer } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";

const deviceID = "wd_4ksk5edkttwsxqx4";
const clientDeviceID = "wd_mw3am46w5weex4a4";
const directPath = "/v1/direct-authorize/" + deviceID;
const body = JSON.stringify({ client_device_id: clientDeviceID });
const root = await mkdtemp(join(tmpdir(), "wedecent-relay-do-"));

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

function startWorker(port, persistTo, globalLimit, ipLimit = 10_000, extraVars = {}) {
  const args = [
    "--no-install", "wrangler", "dev", "--local",
    "--ip", "127.0.0.1",
    "--port", String(port),
    "--persist-to", persistTo,
    "--var", "RELAY_DIRECT_GLOBAL_REQUESTS_PER_WINDOW:" + globalLimit,
    "--var", "RELAY_DIRECT_IP_REQUESTS_PER_WINDOW:" + ipLimit,
  ];
  for (const [key, value] of Object.entries(extraVars)) {
    args.push("--var", key + ":" + value);
  }
  const child = spawn("npx", args, {
    cwd: process.cwd(),
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let logs = "";
  const capture = (chunk) => {
    logs = (logs + chunk.toString()).slice(-16_000);
  };
  child.stdout.on("data", capture);
  child.stderr.on("data", capture);
  return { child, get logs() { return logs; } };
}

async function waitForHealth(worker, baseURL) {
  for (let attempt = 0; attempt < 300; attempt++) {
    if (worker.child.exitCode !== null || worker.child.signalCode !== null) {
      throw new Error("Wrangler dev exited before becoming healthy:\n" + worker.logs);
    }
    try {
      const response = await fetch(baseURL + "/healthz");
      if (response.status === 200) {
        await response.arrayBuffer();
        return;
      }
    } catch {
      // The local Worker is still starting.
    }
    await delay(100);
  }
  throw new Error("Wrangler dev health timeout:\n" + worker.logs);
}

async function stopWorker(worker) {
  const child = worker.child;
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {
    child.kill("SIGTERM");
  }
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    delay(5_000),
  ]);
  if (child.exitCode === null && child.signalCode === null) {
    try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
  }
}

async function withWorker(port, persistTo, globalLimit, ipLimit, operation, extraVars = {}) {
  const worker = startWorker(port, persistTo, globalLimit, ipLimit, extraVars);
  const baseURL = "http://127.0.0.1:" + port;
  try {
    await waitForHealth(worker, baseURL);
    return await operation(baseURL, worker);
  } finally {
    await stopWorker(worker);
  }
}

async function postDirect(baseURL, requestBody = body) {
  const response = await fetch(baseURL + directPath, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: requestBody,
  });
  await response.arrayBuffer();
  return response;
}

async function verifyDurableObjectPersistence() {
  const port = await freePort();
  const persistTo = join(root, "quota-state");

  await withWorker(port, persistTo, 10, 10_000, async (baseURL) => {
    const readiness = await fetch(baseURL + "/readyz");
    await readiness.arrayBuffer();
    assert.equal(readiness.status, 200, "local Durable Object bindings should be ready");

    const unsupported = await fetch(baseURL + directPath, { method: "GET" });
    await unsupported.arrayBuffer();
    assert.equal(unsupported.status, 405);

    const malformed = await fetch(baseURL + "/v1/direct-authorize/not-a-device", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    await malformed.arrayBuffer();
    assert.equal(malformed.status, 400);

    const oversizedStream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("x".repeat(1100)));
        controller.close();
      },
    });
    const oversized = await fetch(baseURL + directPath, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: oversizedStream,
      duplex: "half",
    });
    await oversized.arrayBuffer();
    assert.equal(oversized.status, 413, "chunked oversized body must be bounded");

    for (let i = 0; i < 9; i++) {
      const response = await postDirect(baseURL);
      assert.equal(response.status, 401, "valid preflight should reach authorization");
    }
    const saturated = await postDirect(baseURL);
    assert.equal(saturated.status, 429, "global quota should reject after ten charged requests");
  });

  await withWorker(port, persistTo, 10, 10_000, async (baseURL) => {
    const afterRestart = await postDirect(baseURL);
    assert.equal(afterRestart.status, 429, "SQLite Durable Object state must survive worker restart");
  });
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function base32NoPadding(bytes) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    if (bits > 24) value &= (1 << bits) - 1;
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function createAgentCredentials(slot = 1) {
  const agent = generateKeyPairSync("ed25519");
  const agentSPKI = agent.publicKey.export({ format: "der", type: "spki" });
  const agentPublicKey = agentSPKI.subarray(agentSPKI.length - 32);
  const deviceID = "wd_" + base32NoPadding(createHash("sha256").update(agentPublicKey).digest().subarray(0, 10));
  const issuedAt = Math.floor(Date.now() / 1000);
  const ticketClaims = {
    v: 2,
    aud: "wedecent-relay",
    iss: deviceID,
    sub: deviceID,
    role: "agent",
    iat: issuedAt,
    exp: issuedAt + 90,
    jti: base64url(randomBytes(16)),
    pk: base64url(agentPublicKey),
    slot,
  };
  const ticketPayload = base64url(Buffer.from(JSON.stringify(ticketClaims)));
  const ticketInput = "wedecent-relay-ticket-v2\n" + ticketPayload;
  const relayTicket = "wdt2." + ticketPayload + "." + base64url(sign(null, Buffer.from(ticketInput), agent.privateKey));

  const controlPlane = generateKeyPairSync("ed25519");
  const controlSPKI = controlPlane.publicKey.export({ format: "der", type: "spki" });
  const jwk = controlPlane.publicKey.export({ format: "jwk" });
  const thumbprintInput = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  const kid = createHash("sha256").update(thumbprintInput).digest("base64url");
  const admissionHeader = { alg: "EdDSA", typ: "JWT", kid };
  const clientDeviceID = deviceID === "wd_mw3am46w5weex4a4" ? "wd_aaaaaaaaaaaaaaaa" : "wd_mw3am46w5weex4a4";
  const admissionClaims = {
    grant_id: randomUUID(),
    organization_id: null,
    client_device_id: clientDeviceID,
    target_device_id: deviceID,
    permission: "terminal.connect",
    purpose: "relay.agent.connect",
    slot,
    iss: "wedecent-control-plane",
    aud: "wedecent-relay-agent",
    sub: randomUUID(),
    jti: randomUUID(),
    iat: issuedAt,
    exp: issuedAt + 90,
  };
  const admissionInput = base64url(Buffer.from(JSON.stringify(admissionHeader))) + "." +
    base64url(Buffer.from(JSON.stringify(admissionClaims)));
  const agentAdmission = admissionInput + "." + base64url(sign(null, Buffer.from(admissionInput), controlPlane.privateKey));

  return {
    deviceID,
    relayTicket,
    agentAdmission,
    publicSPKIB64: controlSPKI.toString("base64"),
  };
}

async function websocketUpgradeStatus(port, deviceID, relayTicket, agentAdmission) {
  return new Promise((resolve, reject) => {
    const socket = connect(port, "127.0.0.1");
    let response = Buffer.alloc(0);
    let settled = false;
    const finish = (error, status) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      socket.destroy();
      if (error) reject(error);
      else resolve(status);
    };
    const timeout = setTimeout(() => finish(new Error("WebSocket upgrade timed out")), 10_000);
    socket.on("connect", () => {
      const key = randomBytes(16).toString("base64");
      socket.write([
        "GET /v1/stream/" + deviceID + "?role=agent&slot=1 HTTP/1.1",
        "Host: 127.0.0.1:" + port,
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Key: " + key,
        "Authorization: Bearer " + relayTicket,
        "X-WeDecent-Agent-Admission: " + agentAdmission,
        "",
        "",
      ].join("\r\n"));
    });
    socket.on("data", (chunk) => {
      response = Buffer.concat([response, chunk]);
      const end = response.indexOf("\r\n\r\n");
      if (end < 0) return;
      const statusLine = response.subarray(0, end).toString("latin1").split("\r\n")[0];
      const match = /^HTTP\/1\.[01] (\d{3})/.exec(statusLine);
      if (!match) return finish(new Error("invalid WebSocket response: " + statusLine));
      finish(null, Number(match[1]));
    });
    socket.on("error", (error) => finish(error));
    socket.on("close", () => {
      if (!settled) finish(new Error("WebSocket closed before response headers"));
    });
  });
}

async function verifyAgentReplayPersistence() {
  const port = await freePort();
  const persistTo = join(root, "agent-state");
  const credentials = createAgentCredentials(1);
  const extraVars = { WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64: credentials.publicSPKIB64 };

  await withWorker(port, persistTo, 10_000, 10_000, async () => {
    const status = await websocketUpgradeStatus(port, credentials.deviceID, credentials.relayTicket, credentials.agentAdmission);
    assert.equal(status, 101, "signed enrolled agent should be admitted once");
  }, extraVars);

  await withWorker(port, persistTo, 10_000, 10_000, async () => {
    const replay = await websocketUpgradeStatus(port, credentials.deviceID, credentials.relayTicket, credentials.agentAdmission);
    assert.equal(replay, 409, "agent admission and relay-ticket replay state must survive Worker restart");
  }, extraVars);
}

async function measureCentralLimiter() {
  const port = await freePort();
  await withWorker(port, join(root, "performance-state"), 10_000, 10_000, async (baseURL) => {
    const readiness = await fetch(baseURL + "/readyz");
    await readiness.arrayBuffer();
    assert.equal(readiness.status, 200, "local limiter and relay Durable Objects should be available");

    const requestCount = 128;
    const started = performance.now();
    const results = await Promise.all(Array.from({ length: requestCount }, async () => {
      const requestStarted = performance.now();
      const response = await postDirect(baseURL);
      return { status: response.status, latencyMS: performance.now() - requestStarted };
    }));
    const elapsedMS = performance.now() - started;
    assert.equal(results.filter((result) => result.status === 401).length, requestCount);
    assert.equal(results.filter((result) => result.status === 429 || result.status >= 500).length, 0);

    const latencies = results.map((result) => result.latencyMS).sort((a, b) => a - b);
    const percentile = (p) => latencies[Math.min(latencies.length - 1, Math.ceil(p * latencies.length) - 1)];
    const metrics = {
      runtime: "wrangler-local-sqlite-durable-objects",
      requests: requestCount,
      elapsed_ms: Number(elapsedMS.toFixed(2)),
      throughput_rps: Number((requestCount / (elapsedMS / 1000)).toFixed(2)),
      p50_ms: Number(percentile(0.50).toFixed(2)),
      p95_ms: Number(percentile(0.95).toFixed(2)),
      max_ms: Number(latencies.at(-1).toFixed(2)),
    };
    console.log("RELAY_DO_LOCAL_PERFORMANCE " + JSON.stringify(metrics));
    assert.ok(metrics.p95_ms < 10_000, "local Durable Object p95 must remain bounded");
  });
}

try {
  await verifyDurableObjectPersistence();
  await verifyAgentReplayPersistence();
  await measureCentralLimiter();
} finally {
  await rm(root, { recursive: true, force: true });
}
