const DEFAULT_WINDOW_SECONDS = 60;
const DEFAULT_IP_CONNECTIONS_PER_WINDOW = 120;
const DEFAULT_DEVICE_CONNECTIONS_PER_WINDOW = 240;
const DEFAULT_GLOBAL_STREAM_CONNECTIONS_PER_WINDOW = 12000;
const DEFAULT_DIRECT_IP_REQUESTS_PER_WINDOW = 30;
const DEFAULT_DIRECT_DEVICE_REQUESTS_PER_WINDOW = 60;
const DEFAULT_DIRECT_GLOBAL_REQUESTS_PER_WINDOW = 600;
const DEFAULT_LEGACY_AGENT_CONNECTIONS_PER_WINDOW = 240;
const MAX_WINDOW_SECONDS = 3600;
const MAX_CONNECTIONS_PER_WINDOW = 1000000;
export const MAX_RATE_LIMIT_BUCKETS_PER_SCOPE = 4096;
export const RATE_LIMIT_CLEANUP_INTERVAL_MS = 60_000;
export const RATE_LIMIT_OBJECT_NAME = "relay-rate-limit-v2";
const INTERNAL_CONSUME_URL = "https://wedecent.internal/consume";
const UNKNOWN_SOURCE = "unknown";
const DEVICE_ID = /^wd_[a-z2-7]{16}$/;
const IDENTITY_SCOPES = ["stream-ip", "stream-device", "direct-ip", "direct-device"];
const GLOBAL_SCOPES = new Set(["stream-global", "direct-global", "stream-legacy-agent"]);
const ALLOWED_SCOPES = new Set([...IDENTITY_SCOPES, ...GLOBAL_SCOPES]);
const encoder = new TextEncoder();

export function relayRateLimitConfig(env = {}) {
  return {
    windowMS:
      readPositiveInteger(env.RELAY_RATE_LIMIT_WINDOW_SECONDS, DEFAULT_WINDOW_SECONDS, MAX_WINDOW_SECONDS) * 1000,
    ipLimit: readPositiveInteger(
      env.RELAY_IP_CONNECTIONS_PER_WINDOW,
      DEFAULT_IP_CONNECTIONS_PER_WINDOW,
      MAX_CONNECTIONS_PER_WINDOW,
    ),
    deviceLimit: readPositiveInteger(
      env.RELAY_DEVICE_CONNECTIONS_PER_WINDOW,
      DEFAULT_DEVICE_CONNECTIONS_PER_WINDOW,
      MAX_CONNECTIONS_PER_WINDOW,
    ),
    globalStreamLimit: readPositiveInteger(
      env.RELAY_GLOBAL_STREAM_CONNECTIONS_PER_WINDOW,
      DEFAULT_GLOBAL_STREAM_CONNECTIONS_PER_WINDOW,
      MAX_CONNECTIONS_PER_WINDOW,
    ),
    directIPLimit: readPositiveInteger(
      env.RELAY_DIRECT_IP_REQUESTS_PER_WINDOW,
      DEFAULT_DIRECT_IP_REQUESTS_PER_WINDOW,
      MAX_CONNECTIONS_PER_WINDOW,
    ),
    directDeviceLimit: readPositiveInteger(
      env.RELAY_DIRECT_DEVICE_REQUESTS_PER_WINDOW,
      DEFAULT_DIRECT_DEVICE_REQUESTS_PER_WINDOW,
      MAX_CONNECTIONS_PER_WINDOW,
    ),
    directGlobalLimit: readPositiveInteger(
      env.RELAY_DIRECT_GLOBAL_REQUESTS_PER_WINDOW,
      DEFAULT_DIRECT_GLOBAL_REQUESTS_PER_WINDOW,
      MAX_CONNECTIONS_PER_WINDOW,
    ),
    legacyAgentLimit: readPositiveInteger(
      env.RELAY_LEGACY_AGENT_CONNECTIONS_PER_WINDOW,
      DEFAULT_LEGACY_AGENT_CONNECTIONS_PER_WINDOW,
      MAX_CONNECTIONS_PER_WINDOW,
    ),
  };
}

export function consumeTokenBucket(state, nowMS, capacity, windowMS) {
  if (!Number.isFinite(nowMS) || nowMS < 0) {
    throw new Error("invalid rate-limit clock");
  }
  if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > MAX_CONNECTIONS_PER_WINDOW) {
    throw new Error("invalid rate-limit capacity");
  }
  if (!Number.isSafeInteger(windowMS) || windowMS < 1000 || windowMS > MAX_WINDOW_SECONDS * 1000) {
    throw new Error("invalid rate-limit window");
  }

  let tokens = capacity;
  let updatedAtMS = nowMS;
  if (state !== undefined && state !== null) {
    if (
      typeof state !== "object" ||
      !Number.isFinite(state.tokens) ||
      state.tokens < 0 ||
      !Number.isFinite(state.updatedAtMS) ||
      state.updatedAtMS < 0
    ) {
      throw new Error("invalid persisted rate-limit state");
    }
    const previousUpdatedAtMS = state.updatedAtMS;
    const elapsedMS = Math.max(0, nowMS - previousUpdatedAtMS);
    tokens = Math.min(capacity, state.tokens + (elapsedMS * capacity) / windowMS);
    updatedAtMS = Math.max(previousUpdatedAtMS, nowMS);
  }

  if (tokens >= 1) {
    return {
      accepted: true,
      retryAfterMS: 0,
      state: { tokens: tokens - 1, updatedAtMS },
    };
  }

  return {
    accepted: false,
    retryAfterMS: Math.max(1, Math.ceil(((1 - tokens) * windowMS) / capacity)),
    state: { tokens, updatedAtMS },
  };
}

export async function sourceIPBucketName(request) {
  let source = request.headers.get("CF-Connecting-IP")?.trim() ?? "";
  if (!source || source.length > 64 || /[\s,]/.test(source)) {
    source = UNKNOWN_SOURCE;
  }
  return "ip:" + (await hashIdentifier(source));
}

export async function deviceBucketName(deviceID) {
  if (typeof deviceID !== "string" || !DEVICE_ID.test(deviceID)) {
    throw new Error("invalid authenticated device identity");
  }
  return hashIdentifier(deviceID);
}

export async function enforceRelayRequestRateLimit(request, env, kind = "stream") {
  try {
    const config = relayRateLimitConfig(env);
    if (!env.RELAY_RATE_LIMIT || (kind !== "stream" && kind !== "direct")) {
      throw new Error("rate-limit configuration is unavailable");
    }

    const ipBucket = (await sourceIPBucketName(request)).slice(3);
    const buckets =
      kind === "direct"
        ? [
            { scope: "direct-ip", key: ipBucket, capacity: config.directIPLimit },
            { scope: "direct-global", key: "global", capacity: config.directGlobalLimit },
          ]
        : [
            { scope: "stream-ip", key: ipBucket, capacity: config.ipLimit },
            { scope: "stream-global", key: "global", capacity: config.globalStreamLimit },
          ];
    return await consumeRemoteBuckets(env.RELAY_RATE_LIMIT, buckets, config.windowMS);
  } catch {
    return unavailable();
  }
}

export async function enforceRelayLegacyAgentRateLimit(env) {
  try {
    const config = relayRateLimitConfig(env);
    if (!env.RELAY_RATE_LIMIT) {
      throw new Error("rate-limit configuration is unavailable");
    }
    return await consumeRemoteBuckets(
      env.RELAY_RATE_LIMIT,
      [{ scope: "stream-legacy-agent", key: "global", capacity: config.legacyAgentLimit }],
      config.windowMS,
    );
  } catch {
    return unavailable();
  }
}

export async function enforceRelayDeviceRateLimit(env, deviceID, kind = "stream") {
  try {
    const config = relayRateLimitConfig(env);
    if (!env.RELAY_RATE_LIMIT || (kind !== "stream" && kind !== "direct")) {
      throw new Error("rate-limit configuration is unavailable");
    }
    const buckets = [
      {
        scope: kind === "direct" ? "direct-device" : "stream-device",
        key: await deviceBucketName(deviceID),
        capacity: kind === "direct" ? config.directDeviceLimit : config.deviceLimit,
      },
    ];
    return await consumeRemoteBuckets(env.RELAY_RATE_LIMIT, buckets, config.windowMS);
  } catch {
    return unavailable();
  }
}

export async function limiterRequestConfig(request) {
  if (request.method !== "POST" || new URL(request.url).pathname !== "/consume") {
    return null;
  }
  const contentLength = request.headers.get("Content-Length");
  if (contentLength && (!/^[0-9]+$/.test(contentLength) || Number(contentLength) > 2048)) {
    return null;
  }

  let payload;
  try {
    const text = await request.text();
    if (text.length === 0 || text.length > 2048) {
      return null;
    }
    payload = JSON.parse(text);
  } catch {
    return null;
  }
  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    Object.keys(payload).some((key) => key !== "window_ms" && key !== "buckets")
  ) {
    return null;
  }

  const windowMS = readInternalInteger(payload.window_ms, MAX_WINDOW_SECONDS * 1000);
  if (windowMS < 1000 || !Array.isArray(payload.buckets) || payload.buckets.length < 1 || payload.buckets.length > 2) {
    return null;
  }

  const seen = new Set();
  const buckets = [];
  for (const bucket of payload.buckets) {
    if (
      bucket === null ||
      typeof bucket !== "object" ||
      Array.isArray(bucket) ||
      Object.keys(bucket).some((key) => key !== "scope" && key !== "key" && key !== "capacity") ||
      typeof bucket.scope !== "string" ||
      !ALLOWED_SCOPES.has(bucket.scope) ||
      typeof bucket.key !== "string" ||
      typeof bucket.capacity !== "number" ||
      !Number.isSafeInteger(bucket.capacity) ||
      bucket.capacity < 1 ||
      bucket.capacity > MAX_CONNECTIONS_PER_WINDOW ||
      seen.has(bucket.scope)
    ) {
      return null;
    }
    const isGlobal = GLOBAL_SCOPES.has(bucket.scope);
    if ((isGlobal && bucket.key !== "global") || (!isGlobal && !/^[0-9a-f]{64}$/.test(bucket.key))) {
      return null;
    }
    seen.add(bucket.scope);
    buckets.push({ scope: bucket.scope, key: bucket.key, capacity: bucket.capacity });
  }
  return { windowMS, buckets };
}

export function consumeRateLimitBuckets(storage, buckets, windowMS, nowMS) {
  if (
    !storage ||
    typeof storage.get !== "function" ||
    typeof storage.put !== "function" ||
    typeof storage.delete !== "function" ||
    !Array.isArray(buckets) ||
    buckets.length < 1 ||
    buckets.length > 2
  ) {
    throw new Error("invalid rate-limit storage");
  }
  if (!Number.isFinite(nowMS) || nowMS < 0) {
    throw new Error("invalid rate-limit clock");
  }

  const seenScopes = new Set();
  const pendingWrites = new Map();
  const pendingCounts = new Map();
  const saturatedScopes = [];

  for (const bucket of buckets) {
    validateBucket(bucket);
    if (seenScopes.has(bucket.scope)) {
      throw new Error("duplicate rate-limit bucket scope");
    }
    seenScopes.add(bucket.scope);

    const isGlobal = GLOBAL_SCOPES.has(bucket.scope);
    const storageKey = "bucket:" + bucket.scope + ":" + bucket.key;
    let state = storage.get(storageKey);

    if (state !== undefined) {
      if (isGlobal) {
        validatePersistedTokenBucket(state);
      } else {
        validatePersistedBucket(state);
        const expiryWindowMS = Number.isSafeInteger(state.windowMS)
          ? Math.max(state.windowMS, windowMS)
          : windowMS;
        const effectiveExpiryMS = Math.max(state.expiresAtMS, state.updatedAtMS + expiryWindowMS);
        if (effectiveExpiryMS > state.expiresAtMS) {
          state = { ...state, expiresAtMS: effectiveExpiryMS, windowMS: expiryWindowMS };
          storage.put(storageKey, state);
        }
        if (state.expiresAtMS <= nowMS) {
          storage.delete(storageKey);
          decrementBucketCount(storage, bucket.scope, nowMS);
          state = undefined;
        }
      }
    }

    if (state === undefined && !isGlobal) {
      const countKey = "count:" + bucket.scope;
      const count = pendingCounts.has(bucket.scope)
        ? pendingCounts.get(bucket.scope)
        : (() => {
            const storedCount = storage.get(countKey);
            return storedCount === undefined
              ? cleanupRateLimitScope(storage, bucket.scope, nowMS).active
              : readPersistedCount(storedCount);
          })();

      if (count >= MAX_RATE_LIMIT_BUCKETS_PER_SCOPE) {
        // Saturated identity scopes fall back to the already-enforced global quota.
        // Unknown identities never allocate persistent buckets or deny all newcomers.
        saturatedScopes.push(bucket.scope);
        continue;
      }
      pendingCounts.set(bucket.scope, count + 1);
    }

    const result = consumeTokenBucket(state, nowMS, bucket.capacity, windowMS);
    if (!result.accepted) {
      return {
        accepted: false,
        retryAfterMS: result.retryAfterMS,
        scope: bucket.scope,
        saturated: false,
        saturatedScopes,
      };
    }

    const persistedWindowMS = isGlobal
      ? undefined
      : state && Number.isSafeInteger(state.windowMS)
        ? Math.max(state.windowMS, windowMS)
        : windowMS;
    pendingWrites.set(storageKey, {
      ...result.state,
      expiresAtMS: isGlobal ? null : result.state.updatedAtMS + persistedWindowMS,
      ...(isGlobal ? {} : { windowMS: persistedWindowMS }),
    });
  }

  for (const [scope, count] of pendingCounts) {
    storage.put("count:" + scope, count);
  }
  for (const [key, state] of pendingWrites) {
    storage.put(key, state);
  }

  return {
    accepted: true,
    retryAfterMS: 0,
    scope: null,
    saturated: saturatedScopes.length > 0,
    saturatedScopes,
  };
}

export function cleanupExpiredRateLimitBuckets(storage, nowMS) {
  if (!storage || typeof storage.list !== "function" || typeof storage.delete !== "function" || typeof storage.put !== "function") {
    throw new Error("invalid rate-limit storage");
  }
  if (!Number.isFinite(nowMS) || nowMS < 0) {
    throw new Error("invalid rate-limit cleanup clock");
  }

  let deleted = 0;
  let remaining = 0;
  for (const scope of IDENTITY_SCOPES) {
    const result = cleanupRateLimitScope(storage, scope, nowMS);
    deleted += result.deleted;
    remaining += result.active;
  }
  return { deleted, remaining };
}

function cleanupRateLimitScope(storage, scope, nowMS, persistCount = true) {
  let active = 0;
  let deleted = 0;
  let seen = 0;
  for (const [key, storedState] of storage.list({ prefix: "bucket:" + scope + ":", limit: MAX_RATE_LIMIT_BUCKETS_PER_SCOPE + 1 })) {
    let state = storedState;
    seen++;
    if (seen > MAX_RATE_LIMIT_BUCKETS_PER_SCOPE) {
      throw new Error("rate-limit bucket cardinality exceeded");
    }
    validatePersistedBucket(state);
    if (Number.isSafeInteger(state.windowMS)) {
      const effectiveExpiryMS = Math.max(state.expiresAtMS, state.updatedAtMS + state.windowMS);
      if (effectiveExpiryMS > state.expiresAtMS) {
        state = { ...state, expiresAtMS: effectiveExpiryMS };
        storage.put(key, state);
      }
    }
    if (state.expiresAtMS <= nowMS) {
      storage.delete(key);
      deleted++;
    } else {
      active++;
    }
  }
  if (persistCount) storage.put("count:" + scope, active);
  return { active, deleted };
}

async function consumeRemoteBuckets(namespace, buckets, windowMS) {
  if (!namespace || typeof namespace.idFromName !== "function" || typeof namespace.get !== "function") {
    throw new Error("rate-limit durable object binding is missing");
  }
  const objectID = namespace.idFromName(RATE_LIMIT_OBJECT_NAME);
  const stub = namespace.get(objectID);
  if (!stub || typeof stub.fetch !== "function") {
    throw new Error("rate-limit durable object is unavailable");
  }
  const response = await stub.fetch(
    new Request(INTERNAL_CONSUME_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ window_ms: windowMS, buckets }),
    }),
  );
  if (!response.ok) {
    throw new Error("rate-limit durable object rejected internal request");
  }
  const payload = await response.json();
  if (
    payload === null ||
    typeof payload !== "object" ||
    typeof payload.accepted !== "boolean" ||
    !Number.isSafeInteger(payload.retry_after_ms) ||
    payload.retry_after_ms < 0 ||
    (payload.accepted && payload.scope !== null) ||
    (!payload.accepted && !ALLOWED_SCOPES.has(payload.scope))
  ) {
    throw new Error("rate-limit durable object returned invalid response");
  }
  return payload.accepted
    ? { ok: true }
    : limited(scopeLabel(payload.scope), payload.retry_after_ms);
}

function validateBucket(bucket) {
  if (
    bucket === null ||
    typeof bucket !== "object" ||
    !ALLOWED_SCOPES.has(bucket.scope) ||
    typeof bucket.key !== "string" ||
    !Number.isSafeInteger(bucket.capacity) ||
    bucket.capacity < 1 ||
    bucket.capacity > MAX_CONNECTIONS_PER_WINDOW
  ) {
    throw new Error("invalid rate-limit bucket");
  }
  const isGlobal = GLOBAL_SCOPES.has(bucket.scope);
  if ((isGlobal && bucket.key !== "global") || (!isGlobal && !/^[0-9a-f]{64}$/.test(bucket.key))) {
    throw new Error("invalid rate-limit bucket key");
  }
}

function validatePersistedTokenBucket(state) {
  if (
    state === null ||
    typeof state !== "object" ||
    !Number.isFinite(state.tokens) ||
    state.tokens < 0 ||
    !Number.isFinite(state.updatedAtMS) ||
    state.updatedAtMS < 0
  ) {
    throw new Error("invalid persisted rate-limit bucket");
  }
}

function validatePersistedBucket(state) {
  validatePersistedTokenBucket(state);
  if (!Number.isFinite(state.expiresAtMS) || state.expiresAtMS < 0) {
    throw new Error("invalid persisted rate-limit bucket expiry");
  }
  if (
    state.windowMS !== undefined &&
    (!Number.isSafeInteger(state.windowMS) || state.windowMS < 1000 || state.windowMS > MAX_WINDOW_SECONDS * 1000)
  ) {
    throw new Error("invalid persisted rate-limit bucket window");
  }
}

function readPersistedCount(value) {
  if (value === undefined) return 0;
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_RATE_LIMIT_BUCKETS_PER_SCOPE) {
    throw new Error("invalid persisted rate-limit bucket count");
  }
  return value;
}

function decrementBucketCount(storage, scope, nowMS) {
  const storedCount = storage.get("count:" + scope);
  if (storedCount === undefined) {
    cleanupRateLimitScope(storage, scope, nowMS);
    return;
  }
  const count = readPersistedCount(storedCount);
  if (count < 1) {
    throw new Error("invalid persisted rate-limit bucket count");
  }
  storage.put("count:" + scope, count - 1);
}

function scopeLabel(scope) {
  if (scope.endsWith("-global")) return "global";
  if (scope.endsWith("-ip")) return "ip";
  if (scope.endsWith("-device")) return "device";
  if (scope === "stream-legacy-agent") return "legacy";
  return "unavailable";
}

function limited(scope, retryAfterMS) {
  return {
    ok: false,
    status: 429,
    message: "Relay connection rate limit exceeded",
    retryAfterSeconds: Math.max(1, Math.ceil(retryAfterMS / 1000)),
    scope,
  };
}

function unavailable() {
  return {
    ok: false,
    status: 503,
    message: "Relay admission unavailable",
    retryAfterSeconds: 1,
    scope: "unavailable",
  };
}

async function hashIdentifier(value) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function readPositiveInteger(value, fallback, maximum) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  const text = String(value);
  if (!/^[1-9][0-9]*$/.test(text)) {
    throw new Error("invalid relay rate-limit configuration");
  }
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) {
    throw new Error("invalid relay rate-limit configuration");
  }
  return parsed;
}

function readInternalInteger(value, maximum) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > maximum) {
    return 0;
  }
  return value;
}
