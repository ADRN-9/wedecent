import assert from "node:assert/strict";
import test from "node:test";

import {
  emitRelayTrace,
  healthProbeRequest,
  metricOutcome,
  recordRelayException,
  recordRelayMetric,
  relayMetricContext,
  relayReadiness,
  withRelayTraceHeader,
} from "../src/observability.js";

const deviceID = "wd_4ksk5edkttwsxqx4";

test("metric context uses bounded labels and omits routing identifiers", () => {
  const context = relayMetricContext(
    new Request(`https://relay.test/v1/stream/${deviceID}?role=client&slot=9`, {
      headers: { "CF-Connecting-IP": "203.0.113.44" },
    }),
  );
  assert.deepEqual(context, { route: "stream", role: "client" });
  assert.equal(JSON.stringify(context).includes(deviceID), false);
  assert.equal(JSON.stringify(context).includes("203.0.113.44"), false);

  assert.deepEqual(relayMetricContext(new Request("https://relay.test/healthz?role=agent")), {
    route: "health",
    role: "none",
  });
  assert.deepEqual(relayMetricContext(new Request("https://relay.test/readyz?role=client")), {
    route: "ready",
    role: "none",
  });
  assert.deepEqual(
    relayMetricContext(new Request(`https://relay.test/v1/status/${deviceID}?role=client`)),
    { route: "status", role: "none" },
  );
  assert.deepEqual(relayMetricContext(new Request("https://relay.test/nope?role=agent")), {
    route: "not_found",
    role: "none",
  });
});

test("metrics contain only aggregate labels and bounded duration", () => {
  const points = [];
  const env = { RELAY_METRICS: { writeDataPoint(point) { points.push(point); } } };
  const context = { route: "stream", role: "agent" };

  recordRelayMetric(env, context, new Response(null, { status: 429 }), 12.7);
  recordRelayException(env, context, Number.POSITIVE_INFINITY);

  assert.deepEqual(points[0], {
    indexes: ["stream"],
    blobs: ["stream", "agent", "429", "rate_limited"],
    doubles: [1, 13],
  });
  assert.deepEqual(points[1], {
    indexes: ["stream"],
    blobs: ["stream", "agent", "500", "exception"],
    doubles: [1, 0],
  });
});

test("telemetry writer failures never escape", () => {
  const env = {
    RELAY_METRICS: {
      writeDataPoint() {
        throw new Error("provider detail");
      },
    },
  };
  assert.doesNotThrow(() => recordRelayMetric(env, { route: "time", role: "none" }, new Response(), 1));
  assert.doesNotThrow(() => recordRelayException(env, { route: "time", role: "none" }, 1));
});

test("structured trace is sanitized and finite", () => {
  const entries = [];
  emitRelayTrace(
    (entry) => entries.push(entry),
    { route: "stream", role: "client" },
    "trace-123",
    503,
    86_500_000,
  );
  assert.equal(entries.length, 1);
  const event = JSON.parse(entries[0]);
  assert.deepEqual(event, {
    event: "relay_request",
    trace_id: "trace-123",
    route: "stream",
    role: "client",
    status: 503,
    outcome: "server_error",
    duration_ms: 86_400_000,
  });
  assert.equal(entries[0].includes(deviceID), false);
});

test("trace response header is attached without replacing existing headers", async () => {
  const response = withRelayTraceHeader(
    new Response("ok", { status: 202, headers: { "Cache-Control": "no-store" } }),
    "trace-abc",
  );
  assert.equal(response.status, 202);
  assert.equal(response.headers.get("X-WeDecent-Trace-ID"), "trace-abc");
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.equal(await response.text(), "ok");
});

test("readiness requires metrics, valid rate-limit config, and both durable objects", async () => {
  const calls = [];
  const env = {
    RELAY_METRICS: { writeDataPoint() {} },
    DEVICE_RELAY: healthyNamespace("device", calls),
    RELAY_RATE_LIMIT: healthyNamespace("limit", calls),
  };
  assert.equal(await relayReadiness(env), true);
  assert.deepEqual(calls.sort(), ["device:health-v1", "limit:health-v1"]);

  assert.equal(await relayReadiness({ ...env, RELAY_METRICS: undefined }), false);
  assert.equal(await relayReadiness({ ...env, DEVICE_RELAY: undefined }), false);
  assert.equal(await relayReadiness({ ...env, RELAY_IP_CONNECTIONS_PER_WINDOW: "0" }), false);
  assert.equal(
    await relayReadiness({ ...env, RELAY_RATE_LIMIT: healthyNamespace("limit", [], 500) }),
    false,
  );
});

test("health probe parser accepts only GET /health", () => {
  assert.equal(healthProbeRequest(new Request("https://wedecent.internal/health")), true);
  assert.equal(
    healthProbeRequest(new Request("https://wedecent.internal/health", { method: "POST" })),
    false,
  );
  assert.equal(healthProbeRequest(new Request("https://wedecent.internal/status")), false);
});

test("outcome labels remain bounded", () => {
  assert.equal(metricOutcome(101), "upgraded");
  assert.equal(metricOutcome(204), "success");
  assert.equal(metricOutcome(400), "rejected");
  assert.equal(metricOutcome(429), "rate_limited");
  assert.equal(metricOutcome(503), "server_error");
});

function healthyNamespace(prefix, calls, status = 204) {
  return {
    idFromName(name) {
      return `${prefix}:${name}`;
    },
    get(name) {
      return {
        async fetch(request) {
          calls.push(name);
          assert.equal(new URL(request.url).pathname, "/health");
          return new Response(null, { status });
        },
      };
    },
  };
}
