const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const STORAGE_PREFIX = "connection-grant-jti:";
const CLOCK_SKEW_MS = 30_000;

export const INTERNAL_GRANT_JTI_HEADER = "X-WeDecent-Internal-Grant-JTI";
export const INTERNAL_GRANT_EXP_HEADER = "X-WeDecent-Internal-Grant-Exp";


export function prepareDeviceRelayRequest(request, replay, connectionGrantHeader) {
  const headers = new Headers(request.headers);
  headers.delete(INTERNAL_GRANT_JTI_HEADER);
  headers.delete(INTERNAL_GRANT_EXP_HEADER);
  headers.delete(connectionGrantHeader);
  headers.delete("Authorization");

  if (replay) {
    headers.set(INTERNAL_GRANT_JTI_HEADER, replay.jti);
    headers.set(INTERNAL_GRANT_EXP_HEADER, String(replay.exp));
  }

  return new Request(request, { headers });
}

export function replayMetadataFromRequest(request) {
  const jti = request.headers.get(INTERNAL_GRANT_JTI_HEADER)?.trim() ?? "";
  const expText = request.headers.get(INTERNAL_GRANT_EXP_HEADER)?.trim() ?? "";
  if (!UUID.test(jti) || !/^[0-9]{1,12}$/.test(expText)) {
    return null;
  }
  const exp = Number.parseInt(expText, 10);
  if (!Number.isSafeInteger(exp) || exp <= 0) {
    return null;
  }
  return { jti: jti.toLowerCase(), exp };
}

export async function consumeConnectionGrant(storage, jti, expSeconds, nowMS = Date.now()) {
  if (!UUID.test(jti) || !Number.isSafeInteger(expSeconds) || expSeconds <= 0 || !Number.isSafeInteger(nowMS)) {
    throw new Error("invalid connection grant replay metadata");
  }

  const expiresAtMS = expSeconds * 1000 + CLOCK_SKEW_MS;
  if (!Number.isSafeInteger(expiresAtMS) || expiresAtMS < nowMS) {
    return { accepted: false, expiresAtMS };
  }

  const key = STORAGE_PREFIX + jti.toLowerCase();
  const accepted = await storage.transaction(async (txn) => {
    const existing = await txn.get(key);
    if (existing !== undefined) {
      return false;
    }
    await txn.put(key, expiresAtMS);
    return true;
  });

  return { accepted, expiresAtMS };
}

export async function scheduleReplayCleanup(storage, expiresAtMS) {
  const current = await storage.getAlarm();
  if (current === null || expiresAtMS < current) {
    await storage.setAlarm(expiresAtMS);
  }
}

export async function cleanupExpiredConnectionGrants(storage, nowMS = Date.now()) {
  const entries = await storage.list({ prefix: STORAGE_PREFIX });
  let nextAlarm = null;

  for (const [key, value] of entries) {
    const expiresAtMS = Number(value);
    if (!Number.isSafeInteger(expiresAtMS) || expiresAtMS <= nowMS) {
      await storage.delete(key);
      continue;
    }
    if (nextAlarm === null || expiresAtMS < nextAlarm) {
      nextAlarm = expiresAtMS;
    }
  }

  if (nextAlarm !== null) {
    await storage.setAlarm(nextAlarm);
  }
}
