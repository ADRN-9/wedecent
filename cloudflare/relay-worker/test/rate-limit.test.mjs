import assert from "node:assert/strict";
import test from "node:test";

import {
  cleanupExpiredRateLimitBuckets,
  consumeRateLimitBuckets,
  consumeTokenBucket,
  deviceBucketName,
  enforceRelayDeviceRateLimit,
  enforceRelayLegacyAgentRateLimit,
  enforceRelayRequestRateLimit,
  limiterRequestConfig,
  MAX_RATE_LIMIT_BUCKETS_PER_SCOPE,
  relayRateLimitConfig,
  sourceIPBucketName,
} from "../src/rate-limit.js";

const deviceID = "wd_4ksk5edkttwsxqx4";

test("uses bounded production defaults and rejects invalid overrides", () => {
  assert.deepEqual(relayRateLimitConfig({}), {
    windowMS: 60_000,
    ipLimit: 120,
    deviceLimit: 240,
    globalStreamLimit: 12_000,
    legacyAgentLimit: 240,
    directIPLimit: 30,
    directDeviceLimit: 60,
    directGlobalLimit: 600,
  });
  assert.deepEqual(
    relayRateLimitConfig({
      RELAY_RATE_LIMIT_WINDOW_SECONDS: "30",
      RELAY_IP_CONNECTIONS_PER_WINDOW: "75",
      RELAY_DEVICE_CONNECTIONS_PER_WINDOW: "150",
      RELAY_GLOBAL_STREAM_CONNECTIONS_PER_WINDOW: "5000",
      RELAY_LEGACY_AGENT_CONNECTIONS_PER_WINDOW: "180",
      RELAY_DIRECT_IP_REQUESTS_PER_WINDOW: "20",
      RELAY_DIRECT_DEVICE_REQUESTS_PER_WINDOW: "40",
      RELAY_DIRECT_GLOBAL_REQUESTS_PER_WINDOW: "300",
    }),
    {
      windowMS: 30_000,
      ipLimit: 75,
      deviceLimit: 150,
      globalStreamLimit: 5000,
      legacyAgentLimit: 180,
      directIPLimit: 20,
      directDeviceLimit: 40,
      directGlobalLimit: 300,
    },
  );
  assert.throws(() => relayRateLimitConfig({ RELAY_IP_CONNECTIONS_PER_WINDOW: "0" }));
  assert.throws(() => relayRateLimitConfig({ RELAY_DEVICE_CONNECTIONS_PER_WINDOW: "1000001" }));
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

test("source IP and device bucket keys are stable hashes without raw identifiers", async () => {
  const request = new Request("https://relay.test/v1/stream/" + deviceID, {
    headers: { "CF-Connecting-IP": "203.0.113.17" },
  });
  const first = await sourceIPBucketName(request);
  const second = await sourceIPBucketName(request);
  assert.equal(first, second);
  assert.match(first, /^ip:[0-9a-f]{64}$/);
  assert.equal(first.includes("203.0.113.17"), false);

  const firstDeviceKey = await deviceBucketName(deviceID);
  assert.equal(firstDeviceKey, await deviceBucketName(deviceID));
  assert.match(firstDeviceKey, /^[0-9a-f]{64}$/);
  assert.equal(firstDeviceKey.includes(deviceID), false);
  await assert.rejects(() => deviceBucketName("wd_123"));
});

test("arbitrary unauthenticated target IDs never become device bucket identities", async () => {
  const namespace = fakeNamespace();
  const limiterEnv = env(namespace, {
    RELAY_IP_CONNECTIONS_PER_WINDOW: "10000",
    RELAY_GLOBAL_STREAM_CONNECTIONS_PER_WINDOW: "10000",
  });
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  for (let i = 0; i < 500; i++) {
    const target = "wd_" + "a".repeat(14) + alphabet[Math.floor(i / 32)] + alphabet[i % 32];
    assert.match(target, /^wd_[a-z2-7]{16}$/);
    const result = await enforceRelayRequestRateLimit(streamRequest("192.0.2.20", target), limiterEnv, "stream");
    assert.equal(result.ok, true);
  }
  assert.deepEqual([...new Set(namespace.objectNames)], ["relay-rate-limit-v2"]);
  assert.equal(namespace.storage.get("count:stream-ip"), 1);
  assert.equal(namespace.storage.get("count:stream-device"), undefined);
  assert.equal([...namespace.storage.keys()].filter((key) => key.startsWith("bucket:")).length, 2);
});

test("distributed source IP requests share a global stream quota", async () => {
  const namespace = fakeNamespace();
  const limiterEnv = env(namespace, {
    RELAY_IP_CONNECTIONS_PER_WINDOW: "10",
    RELAY_GLOBAL_STREAM_CONNECTIONS_PER_WINDOW: "2",
  });
  assert.equal((await enforceRelayRequestRateLimit(streamRequest("192.0.2.21"), limiterEnv, "stream")).ok, true);
  assert.equal((await enforceRelayRequestRateLimit(streamRequest("192.0.2.22"), limiterEnv, "stream")).ok, true);
  const rejected = await enforceRelayRequestRateLimit(streamRequest("192.0.2.23"), limiterEnv, "stream");
  assert.equal(rejected.ok, false);
  assert.equal(rejected.status, 429);
  assert.equal(rejected.scope, "global");
  assert.deepEqual([...new Set(namespace.objectNames)], ["relay-rate-limit-v2"]);
});

test("direct authorization requests are throttled per IP and across distributed IPs", async () => {
  const namespace = fakeNamespace();
  const limiterEnv = env(namespace, {
    RELAY_DIRECT_IP_REQUESTS_PER_WINDOW: "2",
    RELAY_DIRECT_GLOBAL_REQUESTS_PER_WINDOW: "3",
  });
  assert.equal((await enforceRelayRequestRateLimit(streamRequest("192.0.2.30"), limiterEnv, "direct")).ok, true);
  assert.equal((await enforceRelayRequestRateLimit(streamRequest("192.0.2.30"), limiterEnv, "direct")).ok, true);
  const repeated = await enforceRelayRequestRateLimit(streamRequest("192.0.2.30"), limiterEnv, "direct");
  assert.equal(repeated.ok, false);
  assert.equal(repeated.scope, "ip");

  assert.equal((await enforceRelayRequestRateLimit(streamRequest("192.0.2.31"), limiterEnv, "direct")).ok, true);
  const distributed = await enforceRelayRequestRateLimit(streamRequest("192.0.2.32"), limiterEnv, "direct");
  assert.equal(distributed.ok, false);
  assert.equal(distributed.scope, "global");
});

test("legacy shared-token agents share one bounded migration quota", async () => {
  const namespace = fakeNamespace();
  const limiterEnv = env(namespace, { RELAY_LEGACY_AGENT_CONNECTIONS_PER_WINDOW: "1" });
  assert.equal((await enforceRelayLegacyAgentRateLimit(limiterEnv)).ok, true);
  const rejected = await enforceRelayLegacyAgentRateLimit(limiterEnv);
  assert.equal(rejected.ok, false);
  assert.equal(rejected.scope, "legacy");
  assert.equal([...namespace.storage.keys()].filter((key) => key.startsWith("bucket:stream-legacy-agent:")).length, 1);
});

test("verified device identity receives a separate bounded device quota", async () => {
  const namespace = fakeNamespace();
  const limiterEnv = env(namespace, { RELAY_DEVICE_CONNECTIONS_PER_WINDOW: "1" });
  assert.equal((await enforceRelayDeviceRateLimit(limiterEnv, deviceID, "stream")).ok, true);
  const rejected = await enforceRelayDeviceRateLimit(limiterEnv, deviceID, "stream");
  assert.equal(rejected.ok, false);
  assert.equal(rejected.scope, "device");
  assert.equal(namespace.storage.get("count:stream-device"), 1);
  assert.equal([...namespace.storage.keys()].some((key) => key.includes(deviceID)), false);
});

test("direct authorization has its own verified-device quota", async () => {
  const namespace = fakeNamespace();
  const limiterEnv = env(namespace, { RELAY_DIRECT_DEVICE_REQUESTS_PER_WINDOW: "1" });
  assert.equal((await enforceRelayDeviceRateLimit(limiterEnv, deviceID, "direct")).ok, true);
  const rejected = await enforceRelayDeviceRateLimit(limiterEnv, deviceID, "direct");
  assert.equal(rejected.ok, false);
  assert.equal(rejected.scope, "device");
  assert.equal(namespace.storage.get("count:direct-device"), 1);
});

test("bucket cardinality saturation falls back to global admission and recovers", () => {
  const storage = createStorage();
  const now = 10_000;
  for (let i = 0; i < MAX_RATE_LIMIT_BUCKETS_PER_SCOPE; i++) {
    const key = i.toString(16).padStart(64, "0");
    const result = consumeRateLimitBuckets(storage, [{ scope: "stream-ip", key, capacity: 10_000 }], 60_000, now);
    assert.equal(result.accepted, true);
  }

  const legitimate = "f".repeat(64);
  const overflow = consumeRateLimitBuckets(
    storage,
    [
      { scope: "stream-ip", key: legitimate, capacity: 10_000 },
      { scope: "stream-global", key: "global", capacity: 10_000 },
    ],
    60_000,
    now,
  );
  assert.equal(overflow.accepted, true);
  assert.equal(overflow.saturated, true);
  assert.deepEqual(overflow.saturatedScopes, ["stream-ip"]);
  assert.equal(storage.get("count:stream-ip"), MAX_RATE_LIMIT_BUCKETS_PER_SCOPE);
  assert.equal(storage.get("bucket:stream-ip:" + legitimate), undefined);
  assert.equal([...storage.keys()].filter((key) => key.startsWith("bucket:stream-ip:")).length, MAX_RATE_LIMIT_BUCKETS_PER_SCOPE);

  const cleanup = cleanupExpiredRateLimitBuckets(storage, now + 60_000);
  assert.equal(cleanup.deleted, MAX_RATE_LIMIT_BUCKETS_PER_SCOPE);
  assert.equal(cleanup.remaining, 0);

  const recovered = consumeRateLimitBuckets(
    storage,
    [
      { scope: "stream-ip", key: legitimate, capacity: 10_000 },
      { scope: "stream-global", key: "global", capacity: 10_000 },
    ],
    60_000,
    now + 60_000,
  );
  assert.equal(recovered.accepted, true);
  assert.equal(storage.get("count:stream-ip"), 1);
  assert.notEqual(storage.get("bucket:stream-ip:" + legitimate), undefined);
});

test("a globally rejected request does not allocate a new identity bucket", () => {
  const storage = createStorage();
  const global = { scope: "stream-global", key: "global", capacity: 1 };
  assert.equal(consumeRateLimitBuckets(storage, [global], 60_000, 1_000).accepted, true);

  const identity = { scope: "stream-ip", key: "e".repeat(64), capacity: 10 };
  const rejected = consumeRateLimitBuckets(storage, [identity, global], 60_000, 1_000);
  assert.equal(rejected.accepted, false);
  assert.equal(rejected.scope, "stream-global");
  assert.equal(storage.get("count:stream-ip"), undefined);
  assert.equal(storage.get("bucket:stream-ip:" + identity.key), undefined);
});

test("bucket expiry follows the effective persisted timestamp through clock rollback", () => {
  const storage = createStorage();
  const key = "d".repeat(64);
  assert.equal(
    consumeRateLimitBuckets(storage, [{ scope: "stream-ip", key, capacity: 2 }], 1_000, 10_000).accepted,
    true,
  );
  assert.equal(
    consumeRateLimitBuckets(storage, [{ scope: "stream-ip", key, capacity: 2 }], 1_000, 5_000).accepted,
    true,
  );

  const persisted = storage.get("bucket:stream-ip:" + key);
  assert.equal(persisted.updatedAtMS, 10_000);
  assert.equal(persisted.expiresAtMS, 11_000);
  assert.equal(persisted.windowMS, 1_000);

  assert.deepEqual(cleanupExpiredRateLimitBuckets(storage, 6_000), { deleted: 0, remaining: 1 });
  assert.deepEqual(cleanupExpiredRateLimitBuckets(storage, 11_000), { deleted: 1, remaining: 0 });
});

test("thousands of arbitrary source IPs and device IDs cannot exhaust admission for newcomers", async () => {
  const namespace = fakeNamespace();
  const limiterEnv = env(namespace, {
    RELAY_IP_CONNECTIONS_PER_WINDOW: "1",
    RELAY_DEVICE_CONNECTIONS_PER_WINDOW: "1",
    RELAY_GLOBAL_STREAM_CONNECTIONS_PER_WINDOW: "10000",
  });
  for (let i = 0; i < 4_500; i++) {
    const ip = "198.51." + Math.floor(i / 256) + "." + (i % 256);
    const result = await enforceRelayRequestRateLimit(streamRequest(ip), limiterEnv, "stream");
    assert.equal(result.ok, true, "source IP " + i + " should use bounded overflow admission");
  }
  assert.equal(namespace.storage.get("count:stream-ip"), MAX_RATE_LIMIT_BUCKETS_PER_SCOPE);

  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  const deviceFor = (index) => {
    let value = index;
    let suffix = "";
    for (let i = 0; i < 16; i++) {
      suffix = alphabet[value % 32] + suffix;
      value = Math.floor(value / 32);
    }
    return "wd_" + suffix;
  };
  for (let i = 0; i < 4_500; i++) {
    const result = await enforceRelayDeviceRateLimit(limiterEnv, deviceFor(i), "stream");
    assert.equal(result.ok, true, "device " + i + " should use bounded overflow admission");
  }
  assert.equal(namespace.storage.get("count:stream-device"), MAX_RATE_LIMIT_BUCKETS_PER_SCOPE);
  assert.equal((await enforceRelayDeviceRateLimit(limiterEnv, deviceFor(0), "stream")).ok, false);
  assert.equal((await enforceRelayDeviceRateLimit(limiterEnv, deviceFor(4_499), "stream")).ok, true);
});

test("bucket expiration and alarm cleanup release bounded cardinality", () => {
  const storage = createStorage();
  const key = "a".repeat(64);
  const first = consumeRateLimitBuckets(storage, [{ scope: "stream-ip", key, capacity: 1 }], 1_000, 1_000);
  assert.equal(first.accepted, true);
  assert.equal(storage.get("count:stream-ip"), 1);

  const beforeExpiry = cleanupExpiredRateLimitBuckets(storage, 1_999);
  assert.deepEqual(beforeExpiry, { deleted: 0, remaining: 1 });
  const afterExpiry = cleanupExpiredRateLimitBuckets(storage, 2_000);
  assert.deepEqual(afterExpiry, { deleted: 1, remaining: 0 });
  assert.equal(storage.get("count:stream-ip"), 0);

  const recreated = consumeRateLimitBuckets(storage, [{ scope: "stream-ip", key, capacity: 1 }], 1_000, 2_000);
  assert.equal(recreated.accepted, true);
  assert.equal(storage.get("count:stream-ip"), 1);
});

test("concurrent bucket creation is atomic and does not overcount", async () => {
  const storage = createStorage();
  const key = "b".repeat(64);
  const results = await Promise.all(
    Array.from({ length: 32 }, () =>
      Promise.resolve().then(() =>
        consumeRateLimitBuckets(storage, [{ scope: "stream-device", key, capacity: 1 }], 60_000, 5_000),
      ),
    ),
  );
  assert.equal(results.filter((result) => result.accepted).length, 1);
  assert.equal(storage.get("count:stream-device"), 1);
});

test("missing bucket-count metadata is rebuilt before admitting new identities", () => {
  const storage = createStorage();
  storage.put("bucket:stream-ip:" + "1".repeat(64), {
    tokens: 1,
    updatedAtMS: 1_000,
    expiresAtMS: 61_000,
  });
  const result = consumeRateLimitBuckets(
    storage,
    [{ scope: "stream-ip", key: "2".repeat(64), capacity: 10 }],
    60_000,
    1_000,
  );
  assert.equal(result.accepted, true);
  assert.equal(storage.get("count:stream-ip"), 2);
});

test("limiter state survives a Durable Object instance restart", () => {
  const backing = new Map();
  const firstInstance = createStorage(backing);
  const key = "c".repeat(64);
  assert.equal(consumeRateLimitBuckets(firstInstance, [{ scope: "stream-device", key, capacity: 1 }], 60_000, 8_000).accepted, true);

  const restartedInstance = createStorage(backing);
  const second = consumeRateLimitBuckets(
    restartedInstance,
    [{ scope: "stream-device", key, capacity: 1 }],
    60_000,
    8_000,
  );
  assert.equal(second.accepted, false);
});

test("limiter outages, storage corruption and malformed responses fail closed without details", async () => {
  const throwing = {
    idFromName() {
      throw new Error("provider detail with 192.0.2.40 and " + deviceID);
    },
  };
  const unavailable = await enforceRelayRequestRateLimit(
    streamRequest("192.0.2.40"),
    env(throwing),
    "stream",
  );
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.message.includes("192.0.2.40"), false);
  assert.equal(unavailable.message.includes(deviceID), false);

  const corruptedStorage = createStorage();
  corruptedStorage.put("bucket:stream-global:global", {
    tokens: -1,
    updatedAtMS: 0,
    expiresAtMS: null,
  });
  const corrupted = fakeNamespace({ storage: corruptedStorage });
  const storageFailure = await enforceRelayRequestRateLimit(streamRequest("192.0.2.41"), env(corrupted), "stream");
  assert.equal(storageFailure.status, 503);

  const malformedGlobalStorage = createStorage();
  malformedGlobalStorage.put("bucket:stream-global:global", null);
  const malformedGlobal = fakeNamespace({ storage: malformedGlobalStorage });
  const malformedGlobalResult = await enforceRelayRequestRateLimit(
    streamRequest("192.0.2.43"),
    env(malformedGlobal),
    "stream",
  );
  assert.equal(malformedGlobalResult.status, 503);

  const malformed = {
    idFromName: () => "relay-rate-limit-v2",
    get: () => ({ fetch: async () => Response.json({ accepted: "yes", retry_after_ms: 0, scope: null }) }),
  };
  const malformedResult = await enforceRelayRequestRateLimit(streamRequest("192.0.2.42"), env(malformed), "stream");
  assert.equal(malformedResult.status, 503);
  assert.equal(malformedResult.message, "Relay admission unavailable");
});

test("internal limiter parser accepts only bounded known scopes and hashed keys", async () => {
  const valid = new Request("https://wedecent.internal/consume", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      window_ms: 60_000,
      buckets: [
        { scope: "stream-global", key: "global", capacity: 100 },
        { scope: "stream-ip", key: "e".repeat(64), capacity: 10 },
      ],
    }),
  });
  assert.deepEqual(await limiterRequestConfig(valid), {
    windowMS: 60_000,
    buckets: [
      { scope: "stream-global", key: "global", capacity: 100 },
      { scope: "stream-ip", key: "e".repeat(64), capacity: 10 },
    ],
  });

  const rawIdentifier = new Request("https://wedecent.internal/consume", {
    method: "POST",
    body: JSON.stringify({ window_ms: 60_000, buckets: [{ scope: "stream-ip", key: deviceID, capacity: 10 }] }),
  });
  assert.equal(await limiterRequestConfig(rawIdentifier), null);

  const unknownScope = new Request("https://wedecent.internal/consume", {
    method: "POST",
    body: JSON.stringify({ window_ms: 60_000, buckets: [{ scope: "attacker-chosen", key: "global", capacity: 10 }] }),
  });
  assert.equal(await limiterRequestConfig(unknownScope), null);

  const malformed = new Request("https://wedecent.internal/consume", {
    method: "POST",
    body: JSON.stringify({ window_ms: 0, buckets: [] }),
  });
  assert.equal(await limiterRequestConfig(malformed), null);
});

function streamRequest(ip, target = deviceID) {
  return new Request("https://relay.test/v1/stream/" + target + "?role=client", {
    headers: { "CF-Connecting-IP": ip },
  });
}

function env(namespace, overrides = {}) {
  return {
    RELAY_RATE_LIMIT: namespace,
    RELAY_RATE_LIMIT_WINDOW_SECONDS: "60",
    RELAY_IP_CONNECTIONS_PER_WINDOW: "100",
    RELAY_DEVICE_CONNECTIONS_PER_WINDOW: "100",
    RELAY_GLOBAL_STREAM_CONNECTIONS_PER_WINDOW: "10000",
    RELAY_DIRECT_IP_REQUESTS_PER_WINDOW: "100",
    RELAY_DIRECT_DEVICE_REQUESTS_PER_WINDOW: "100",
    RELAY_DIRECT_GLOBAL_REQUESTS_PER_WINDOW: "10000",
    ...overrides,
  };
}

function fakeNamespace({ storage = createStorage(), now = 1_000 } = {}) {
  return {
    storage,
    objectNames: [],
    idFromName(name) {
      this.objectNames.push(name);
      return name;
    },
    get(name) {
      return {
        fetch: async (request) => {
          const config = await limiterRequestConfig(request);
          if (!config) return new Response("invalid", { status: 400 });
          const result = consumeRateLimitBuckets(storage, config.buckets, config.windowMS, now);
          return Response.json({
            accepted: result.accepted,
            retry_after_ms: result.retryAfterMS,
            scope: result.scope,
          });
        },
      };
    },
  };
}

function createStorage(backing = new Map()) {
  return {
    get: (key) => backing.get(key),
    put: (key, value) => backing.set(key, value),
    delete: (key) => backing.delete(key),
    list: ({ prefix, limit } = {}) => {
      const entries = [...backing.entries()].filter(([key]) => !prefix || key.startsWith(prefix));
      return new Map(entries.slice(0, limit));
    },
    keys: () => backing.keys(),
  };
}
