import assert from "node:assert/strict";
import test from "node:test";

import {
  consumeTokenBucket,
  enforceRelayConnectionRateLimit,
  limiterRequestConfig,
  relayRateLimitConfig,
  sourceIPBucketName,
} from "../src/rate-limit.js";

const deviceID = "wd_4ksk5edkttwsxqx4";

test("uses bounded production defaults and rejects invalid overrides", () => {
  assert.deepEqual(relayRateLimitConfig({}), {
    windowMS: 60_000,
    ipLimit: 120,
    deviceLimit: 240,
  });
  assert.deepEqual(
    relayRateLimitConfig({
      RELAY_RATE_LIMIT_WINDOW_SECONDS: "30",
      RELAY_IP_CONNECTIONS_PER_WINDOW: "75",
      RELAY_DEVICE_CONNECTIONS_PER_WINDOW: "150",
    }),
    { windowMS: 30_000, ipLimit: 75, deviceLimit: 150 },
  );
  assert.throws(() => relayRateLimitConfig({ RELAY_IP_CONNECTIONS_PER_WINDOW: "0" }));
  assert.throws(() => relayRateLimitConfig({ RELAY_DEVICE_CONNECTIONS_PER_WINDOW: "10001" }));
  assert.throws(() => relayRateLimitConfig({ RELAY_RATE_LIMIT_WINDOW_SECONDS: "3601" }));
});

test("token bucket enforces burst capacity and refills continuously", () => {
  let state;
  let result = consumeTokenBucket(state, 1_000, 2, 1_000);
  assert.equal(result.accepted, true);
  state = result.state;

  result = consumeTokenBucket(state, 1_000, 2, 1_000);
  assert.equal(result.accepted, true);
  state = result.state;

  result = consumeTokenBucket(state, 1_000, 2, 1_000);
  assert.equal(result.accepted, false);
  assert.equal(result.retryAfterMS, 500);
  state = result.state;

  result = consumeTokenBucket(state, 1_250, 2, 1_000);
  assert.equal(result.accepted, false);
  assert.equal(result.retryAfterMS, 250);

  result = consumeTokenBucket(result.state, 1_500, 2, 1_000);
  assert.equal(result.accepted, true);
});

test("token bucket does not refill when the observed clock moves backward", () => {
  const result = consumeTokenBucket({ tokens: 0, updatedAtMS: 2_000 }, 1_500, 2, 1_000);
  assert.equal(result.accepted, false);
  assert.equal(result.retryAfterMS, 500);
  assert.equal(result.state.updatedAtMS, 2_000);
});

test("token bucket fails closed on malformed persisted state", () => {
  assert.throws(() => consumeTokenBucket({ tokens: -1, updatedAtMS: 0 }, 1_000, 2, 1_000));
  assert.throws(() => consumeTokenBucket({ tokens: 1, updatedAtMS: Number.NaN }, 1_000, 2, 1_000));
});

test("source IP buckets are stable hashes and never contain the raw address", async () => {
  const request = new Request("https://relay.test/v1/stream/" + deviceID, {
    headers: { "CF-Connecting-IP": "203.0.113.17" },
  });
  const first = await sourceIPBucketName(request);
  const second = await sourceIPBucketName(request);
  assert.equal(first, second);
  assert.match(first, /^ip:[0-9a-f]{64}$/);
  assert.equal(first.includes("203.0.113.17"), false);

  const missing = await sourceIPBucketName(new Request("https://relay.test/"));
  const malformed = await sourceIPBucketName(
    new Request("https://relay.test/", { headers: { "CF-Connecting-IP": "203.0.113.1, 198.51.100.1" } }),
  );
  assert.equal(missing, malformed);
});

test("IP rejection short-circuits the device bucket", async () => {
  const namespace = fakeNamespace((name) => {
    if (name.startsWith("ip:")) {
      return { accepted: false, retry_after_ms: 1_501 };
    }
    return { accepted: true, retry_after_ms: 0 };
  });
  const result = await enforceRelayConnectionRateLimit(streamRequest("192.0.2.10"), env(namespace), deviceID);
  assert.deepEqual(result, {
    ok: false,
    status: 429,
    message: "Relay connection rate limit exceeded",
    retryAfterSeconds: 2,
    scope: "ip",
  });
  assert.equal(namespace.calls.length, 1);
  assert.match(namespace.calls[0], /^ip:/);
});

test("device rejection occurs only after the source IP bucket accepts", async () => {
  const namespace = fakeNamespace((name) =>
    name.startsWith("device:")
      ? { accepted: false, retry_after_ms: 100 }
      : { accepted: true, retry_after_ms: 0 },
  );
  const result = await enforceRelayConnectionRateLimit(streamRequest("192.0.2.11"), env(namespace), deviceID);
  assert.equal(result.ok, false);
  assert.equal(result.status, 429);
  assert.equal(result.scope, "device");
  assert.equal(result.retryAfterSeconds, 1);
  assert.equal(namespace.calls.length, 2);
  assert.equal(namespace.calls[1], `device:${deviceID}`);
});

test("limiter outages and malformed responses fail closed without raw details", async () => {
  const throwing = {
    idFromName() {
      throw new Error("provider detail that must not escape");
    },
  };
  const result = await enforceRelayConnectionRateLimit(streamRequest("192.0.2.12"), env(throwing), deviceID);
  assert.deepEqual(result, {
    ok: false,
    status: 503,
    message: "Relay admission unavailable",
    retryAfterSeconds: 1,
    scope: "unavailable",
  });

  const malformed = fakeNamespace(() => ({ accepted: "yes", retry_after_ms: 0 }));
  const malformedResult = await enforceRelayConnectionRateLimit(streamRequest("192.0.2.13"), env(malformed), deviceID);
  assert.equal(malformedResult.status, 503);
  assert.equal(malformedResult.message, "Relay admission unavailable");
});

test("internal limiter request parser accepts only bounded POST consume requests", () => {
  const valid = new Request("https://wedecent.internal/consume", {
    method: "POST",
    headers: {
      "X-WeDecent-Rate-Limit": "120",
      "X-WeDecent-Rate-Window-Ms": "60000",
    },
  });
  assert.deepEqual(limiterRequestConfig(valid), { capacity: 120, windowMS: 60_000 });
  assert.equal(limiterRequestConfig(new Request("https://wedecent.internal/consume")), null);
  assert.equal(
    limiterRequestConfig(
      new Request("https://wedecent.internal/consume", {
        method: "POST",
        headers: { "X-WeDecent-Rate-Limit": "0", "X-WeDecent-Rate-Window-Ms": "60000" },
      }),
    ),
    null,
  );
});

function streamRequest(ip) {
  return new Request(`https://relay.test/v1/stream/${deviceID}?role=client`, {
    headers: { "CF-Connecting-IP": ip },
  });
}

function env(namespace) {
  return {
    RELAY_RATE_LIMIT: namespace,
    RELAY_RATE_LIMIT_WINDOW_SECONDS: "60",
    RELAY_IP_CONNECTIONS_PER_WINDOW: "1",
    RELAY_DEVICE_CONNECTIONS_PER_WINDOW: "1",
  };
}

function fakeNamespace(resolver) {
  return {
    calls: [],
    idFromName(name) {
      return name;
    },
    get(name) {
      return {
        fetch: async () => {
          this.calls.push(name);
          return Response.json(resolver(name));
        },
      };
    },
  };
}
