const DEVICE_ID = /^wd_[a-z2-7]{16}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const STORAGE_PREFIX = "connection-grant-jti:";
const EVIDENCE_PREFIX = "connection-grant-evidence:";
const CLOCK_SKEW_MS = 30_000;
const EVIDENCE_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

export const INTERNAL_GRANT_JTI_HEADER = "X-WeDecent-Internal-Grant-JTI";
export const INTERNAL_GRANT_EXP_HEADER = "X-WeDecent-Internal-Grant-Exp";
export const INTERNAL_GRANT_ID_HEADER = "X-WeDecent-Internal-Grant-ID";
export const INTERNAL_GRANT_CLIENT_HEADER = "X-WeDecent-Internal-Grant-Client";
export const INTERNAL_GRANT_TARGET_HEADER = "X-WeDecent-Internal-Grant-Target";
export const INTERNAL_GRANT_FLOW_HEADER = "X-WeDecent-Internal-Grant-Flow";
export const INTERNAL_GRANT_PERMISSION_HEADER = "X-WeDecent-Internal-Grant-Permission";
export const INTERNAL_GRANT_VALIDATED_AT_HEADER = "X-WeDecent-Internal-Grant-Validated-At";

const INTERNAL_HEADERS = [
  INTERNAL_GRANT_JTI_HEADER,
  INTERNAL_GRANT_EXP_HEADER,
  INTERNAL_GRANT_ID_HEADER,
  INTERNAL_GRANT_CLIENT_HEADER,
  INTERNAL_GRANT_TARGET_HEADER,
  INTERNAL_GRANT_FLOW_HEADER,
  INTERNAL_GRANT_PERMISSION_HEADER,
  INTERNAL_GRANT_VALIDATED_AT_HEADER,
];

export function prepareDeviceRelayRequest(request, replay, connectionGrantHeader) {
  const headers = new Headers(request.headers);
  for (const name of INTERNAL_HEADERS) headers.delete(name);
  headers.delete(connectionGrantHeader);
  headers.delete("Authorization");

  if (replay) {
    headers.set(INTERNAL_GRANT_JTI_HEADER, replay.jti);
    headers.set(INTERNAL_GRANT_EXP_HEADER, String(replay.exp));
    headers.set(INTERNAL_GRANT_ID_HEADER, replay.grantID);
    headers.set(INTERNAL_GRANT_CLIENT_HEADER, replay.clientDeviceID);
    headers.set(INTERNAL_GRANT_TARGET_HEADER, replay.targetDeviceID);
    headers.set(INTERNAL_GRANT_FLOW_HEADER, replay.flow);
    headers.set(INTERNAL_GRANT_PERMISSION_HEADER, replay.permission);
    headers.set(INTERNAL_GRANT_VALIDATED_AT_HEADER, String(replay.validatedAtMS));
  }

  return new Request(request, { headers });
}

export function replayMetadataFromRequest(request) {
  const headers = request.headers;
  const jti = headers.get(INTERNAL_GRANT_JTI_HEADER)?.trim() ?? "";
  const expText = headers.get(INTERNAL_GRANT_EXP_HEADER)?.trim() ?? "";
  const grantID = headers.get(INTERNAL_GRANT_ID_HEADER)?.trim() ?? "";
  const clientDeviceID = headers.get(INTERNAL_GRANT_CLIENT_HEADER)?.trim() ?? "";
  const targetDeviceID = headers.get(INTERNAL_GRANT_TARGET_HEADER)?.trim() ?? "";
  const flow = headers.get(INTERNAL_GRANT_FLOW_HEADER)?.trim() ?? "";
  const permission = headers.get(INTERNAL_GRANT_PERMISSION_HEADER)?.trim() ?? "";
  const validatedText = headers.get(INTERNAL_GRANT_VALIDATED_AT_HEADER)?.trim() ?? "";

  if (
    !UUID.test(jti) ||
    !UUID.test(grantID) ||
    !DEVICE_ID.test(clientDeviceID) ||
    !DEVICE_ID.test(targetDeviceID) ||
    clientDeviceID === targetDeviceID ||
    (flow !== "direct" && flow !== "relay") ||
    permission !== "terminal.connect" ||
    !/^[0-9]{1,12}$/.test(expText) ||
    !/^[0-9]{1,16}$/.test(validatedText)
  ) return null;

  const exp = Number.parseInt(expText, 10);
  const validatedAtMS = Number.parseInt(validatedText, 10);
  if (!Number.isSafeInteger(exp) || exp <= 0 || !Number.isSafeInteger(validatedAtMS) || validatedAtMS <= 0) return null;

  return { jti: jti.toLowerCase(), exp, grantID: grantID.toLowerCase(), clientDeviceID, targetDeviceID, flow, permission, validatedAtMS };
}

export async function consumeConnectionGrant(storage, replay, nowMS = Date.now()) {
  if (
    !replay ||
    !UUID.test(replay.jti) ||
    !UUID.test(replay.grantID) ||
    !DEVICE_ID.test(replay.clientDeviceID) ||
    !DEVICE_ID.test(replay.targetDeviceID) ||
    replay.clientDeviceID === replay.targetDeviceID ||
    (replay.flow !== "direct" && replay.flow !== "relay") ||
    replay.permission !== "terminal.connect" ||
    !Number.isSafeInteger(replay.exp) ||
    replay.exp <= 0 ||
    !Number.isSafeInteger(replay.validatedAtMS) ||
    !Number.isSafeInteger(nowMS)
  ) throw new Error("invalid connection grant replay metadata");

  const expiresAtMS = replay.exp * 1000 + CLOCK_SKEW_MS;
  if (
    !Number.isSafeInteger(expiresAtMS) ||
    expiresAtMS < nowMS ||
    replay.validatedAtMS > nowMS + CLOCK_SKEW_MS ||
    nowMS - replay.validatedAtMS > CLOCK_SKEW_MS
  ) return { accepted: false, reason: "stale", expiresAtMS, evidence: null };

  const jti = replay.jti.toLowerCase();
  const evidence = {
    version: 1,
    grant_id: replay.grantID.toLowerCase(),
    jti,
    client_device_id: replay.clientDeviceID,
    target_device_id: replay.targetDeviceID,
    permission: replay.permission,
    flow: replay.flow,
    validation_outcome: "accepted",
    consumption_outcome: "consumed",
    validated_at: new Date(replay.validatedAtMS).toISOString(),
    consumed_at: new Date(nowMS).toISOString(),
    expires_at: new Date(replay.exp * 1000).toISOString(),
    retain_until_ms: nowMS + EVIDENCE_RETENTION_MS,
  };

  const accepted = await storage.transaction(async (txn) => {
    const existing = await txn.get(STORAGE_PREFIX + jti);
    if (existing !== undefined) return false;
    await txn.put(STORAGE_PREFIX + jti, expiresAtMS);
    await txn.put(EVIDENCE_PREFIX + jti, evidence);
    return true;
  });
  return { accepted, reason: accepted ? "" : "replay", expiresAtMS, evidence: accepted ? evidence : null };
}

export async function readConnectionGrantEvidence(storage, jti) {
  if (!UUID.test(jti)) return null;
  return (await storage.get(EVIDENCE_PREFIX + jti.toLowerCase())) ?? null;
}

export async function scheduleReplayCleanup(storage, expiresAtMS) {
  const current = await storage.getAlarm();
  if (current === null || expiresAtMS < current) await storage.setAlarm(expiresAtMS);
}

export async function cleanupExpiredConnectionGrants(storage, nowMS = Date.now()) {
  const replayEntries = await storage.list({ prefix: STORAGE_PREFIX });
  const evidenceEntries = await storage.list({ prefix: EVIDENCE_PREFIX });
  let nextAlarm = null;

  for (const [key, value] of replayEntries) {
    const expiresAtMS = Number(value);
    if (!Number.isSafeInteger(expiresAtMS) || expiresAtMS <= nowMS) {
      await storage.delete(key);
      continue;
    }
    if (nextAlarm === null || expiresAtMS < nextAlarm) nextAlarm = expiresAtMS;
  }

  for (const [key, value] of evidenceEntries) {
    const retainUntilMS = Number(value?.retain_until_ms);
    if (!Number.isSafeInteger(retainUntilMS) || retainUntilMS <= nowMS) {
      await storage.delete(key);
      continue;
    }
    if (nextAlarm === null || retainUntilMS < nextAlarm) nextAlarm = retainUntilMS;
  }

  if (nextAlarm !== null) await storage.setAlarm(nextAlarm);
}
