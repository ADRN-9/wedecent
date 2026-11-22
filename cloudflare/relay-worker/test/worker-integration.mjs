import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
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

function startWorker(port, persistTo, globalLimit, ipLimit = 10_000) {
  const args = [
    "--no-install", "wrangler", "dev", "--local",
    "--ip", "127.0.0.1",
    "--port", String(port),
    "--persist-to", persistTo,
    "--var", "RELAY_DIRECT_GLOBAL_REQUESTS_PER_WINDOW:" + globalLimit,
    "--var", "RELAY_DIRECT_IP_REQUESTS_PER_WINDOW:" + ipLimit,
  ];
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

async function withWorker(port, persistTo, globalLimit, ipLimit, operation) {
  const worker = startWorker(port, persistTo, globalLimit, ipLimit);
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
  await measureCentralLimiter();
} finally {
  await rm(root, { recursive: true, force: true });
}
