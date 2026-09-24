const DEFAULT_WINDOW_SECONDS = 60;
const DEFAULT_IP_CONNECTIONS_PER_WINDOW = 120;
const DEFAULT_DEVICE_CONNECTIONS_PER_WINDOW = 240;
const MAX_WINDOW_SECONDS = 3600;
const MAX_CONNECTIONS_PER_WINDOW = 10000;
const INTERNAL_LIMIT_HEADER = "X-WeDecent-Rate-Limit";
const INTERNAL_WINDOW_HEADER = "X-WeDecent-Rate-Window-Ms";
const INTERNAL_CONSUME_URL = "https://wedecent.internal/consume";
const UNKNOWN_SOURCE = "unknown";
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
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(source)));
  return `ip:${Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join("")}`;
}

export async function enforceRelayConnectionRateLimit(request, env, deviceId) {
  let config;
  try {
    config = relayRateLimitConfig(env);
    if (!env.RELAY_RATE_LIMIT) {
      throw new Error("rate-limit durable object binding is missing");
    }

    const ipBucket = await sourceIPBucketName(request);
    const ipResult = await consumeRemoteBucket(env.RELAY_RATE_LIMIT, ipBucket, config.ipLimit, config.windowMS);
    if (!ipResult.accepted) {
      return limited("ip", ipResult.retryAfterMS);
    }

    const deviceResult = await consumeRemoteBucket(
      env.RELAY_RATE_LIMIT,
      `device:${deviceId}`,
      config.deviceLimit,
      config.windowMS,
    );
    if (!deviceResult.accepted) {
      return limited("device", deviceResult.retryAfterMS);
    }
    return { ok: true };
  } catch {
    return {
      ok: false,
      status: 503,
      message: "Relay admission unavailable",
      retryAfterSeconds: 1,
      scope: "unavailable",
    };
  }
}

export function limiterRequestConfig(request) {
  if (request.method !== "POST") {
    return null;
  }
  const url = new URL(request.url);
  if (url.pathname !== "/consume") {
    return null;
  }
  const capacity = readInternalInteger(request.headers.get(INTERNAL_LIMIT_HEADER), MAX_CONNECTIONS_PER_WINDOW);
  const windowMS = readInternalInteger(request.headers.get(INTERNAL_WINDOW_HEADER), MAX_WINDOW_SECONDS * 1000);
  if (capacity < 1 || windowMS < 1000) {
    return null;
  }
  return { capacity, windowMS };
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
  if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) {
    return 0;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed <= maximum ? parsed : 0;
}

async function consumeRemoteBucket(namespace, bucketName, capacity, windowMS) {
  const objectId = namespace.idFromName(bucketName);
  const response = await namespace.get(objectId).fetch(
    new Request(INTERNAL_CONSUME_URL, {
      method: "POST",
      headers: {
        [INTERNAL_LIMIT_HEADER]: String(capacity),
        [INTERNAL_WINDOW_HEADER]: String(windowMS),
      },
    }),
  );
  if (!response.ok) {
    throw new Error("rate-limit durable object rejected internal request");
  }
  const payload = await response.json();
  if (
    typeof payload?.accepted !== "boolean" ||
    !Number.isSafeInteger(payload?.retry_after_ms) ||
    payload.retry_after_ms < 0
  ) {
    throw new Error("rate-limit durable object returned invalid response");
  }
  return { accepted: payload.accepted, retryAfterMS: payload.retry_after_ms };
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
