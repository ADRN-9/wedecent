const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RELAY_TICKET_JTI = /^[A-Za-z0-9_-]{22}$/;
const STORAGE_PREFIX = "connection-grant-jti:";
const AGENT_ADMISSION_STORAGE_PREFIX = "agent-admission-jti:";
const RELAY_TICKET_STORAGE_PREFIX = "relay-agent-ticket-jti:";
const CLOCK_SKEW_MS = 30_000;

export const INTERNAL_GRANT_JTI_HEADER = "X-WeDecent-Internal-Grant-JTI";
export const INTERNAL_GRANT_EXP_HEADER = "X-WeDecent-Internal-Grant-Exp";
export const INTERNAL_AGENT_ADMISSION_JTI_HEADER = "X-WeDecent-Internal-Agent-Admission-JTI";
export const INTERNAL_AGENT_ADMISSION_EXP_HEADER = "X-WeDecent-Internal-Agent-Admission-Exp";
export const INTERNAL_RELAY_TICKET_JTI_HEADER = "X-WeDecent-Internal-Relay-Ticket-JTI";
export const INTERNAL_RELAY_TICKET_EXP_HEADER = "X-WeDecent-Internal-Relay-Ticket-Exp";
export const INTERNAL_AGENT_LEGACY_HEADER = "X-WeDecent-Internal-Agent-Legacy";
export const INTERNAL_CLIENT_DEVICE_ID_HEADER = "X-WeDecent-Internal-Client-Device-ID";
const DEVICE_ID = /^wd_[a-z2-7]{16}$/;

export function prepareDeviceRelayRequest(request, replay, connectionGrantHeader, clientDeviceID = "") {
  const headers = new Headers(request.headers);
  for (const name of [
    INTERNAL_GRANT_JTI_HEADER,
    INTERNAL_GRANT_EXP_HEADER,
    INTERNAL_AGENT_ADMISSION_JTI_HEADER,
    INTERNAL_AGENT_ADMISSION_EXP_HEADER,
    INTERNAL_RELAY_TICKET_JTI_HEADER,
    INTERNAL_RELAY_TICKET_EXP_HEADER,
    INTERNAL_AGENT_LEGACY_HEADER,
    INTERNAL_CLIENT_DEVICE_ID_HEADER,
  ]) {
    headers.delete(name);
  }
  headers.delete(connectionGrantHeader);
  headers.delete("X-WeDecent-Agent-Admission");
  headers.delete("Authorization");

  if (replay) {
    headers.set(INTERNAL_GRANT_JTI_HEADER, replay.jti);
    headers.set(INTERNAL_GRANT_EXP_HEADER, String(replay.exp));
  }
  if (clientDeviceID) {
    if (!DEVICE_ID.test(clientDeviceID)) {
      throw new Error("invalid authenticated client device ID");
    }
    headers.set(INTERNAL_CLIENT_DEVICE_ID_HEADER, clientDeviceID);
  }

  return new Request(request, { headers });
}

export function prepareAgentRelayRequest(
  request,
  admissionReplay,
  relayTicketReplay,
  agentAdmissionHeader,
  connectionGrantHeader,
  legacy = false,
) {
  if (!admissionReplay || !UUID.test(admissionReplay.jti) || !Number.isSafeInteger(admissionReplay.exp)) {
    throw new Error("invalid agent admission replay metadata");
  }
  const headers = new Headers(request.headers);
  for (const name of [
    INTERNAL_GRANT_JTI_HEADER,
    INTERNAL_GRANT_EXP_HEADER,
    INTERNAL_AGENT_ADMISSION_JTI_HEADER,
    INTERNAL_AGENT_ADMISSION_EXP_HEADER,
    INTERNAL_RELAY_TICKET_JTI_HEADER,
    INTERNAL_RELAY_TICKET_EXP_HEADER,
    INTERNAL_AGENT_LEGACY_HEADER,
  ]) {
    headers.delete(name);
  }
  headers.delete(agentAdmissionHeader);
  headers.delete(connectionGrantHeader);
  headers.delete("Authorization");

  headers.set(INTERNAL_AGENT_ADMISSION_JTI_HEADER, admissionReplay.jti);
  headers.set(INTERNAL_AGENT_ADMISSION_EXP_HEADER, String(admissionReplay.exp));
  if (relayTicketReplay) {
    if (!RELAY_TICKET_JTI.test(relayTicketReplay.jti) || !Number.isSafeInteger(relayTicketReplay.exp)) {
      throw new Error("invalid relay ticket replay metadata");
    }
    headers.set(INTERNAL_RELAY_TICKET_JTI_HEADER, relayTicketReplay.jti);
    headers.set(INTERNAL_RELAY_TICKET_EXP_HEADER, String(relayTicketReplay.exp));
  }
  headers.set(INTERNAL_AGENT_LEGACY_HEADER, legacy ? "1" : "0");
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

export function agentAdmissionReplayMetadataFromRequest(request) {
  const jti = request.headers.get(INTERNAL_AGENT_ADMISSION_JTI_HEADER)?.trim() ?? "";
  const expText = request.headers.get(INTERNAL_AGENT_ADMISSION_EXP_HEADER)?.trim() ?? "";
  if (!UUID.test(jti) || !/^[0-9]{1,12}$/.test(expText)) {
    return null;
  }
  const exp = Number.parseInt(expText, 10);
  if (!Number.isSafeInteger(exp) || exp <= 0) {
    return null;
  }
  return { jti: jti.toLowerCase(), exp };
}

export function relayTicketReplayMetadataFromRequest(request) {
  const jti = request.headers.get(INTERNAL_RELAY_TICKET_JTI_HEADER)?.trim() ?? "";
  const expText = request.headers.get(INTERNAL_RELAY_TICKET_EXP_HEADER)?.trim() ?? "";
  if (!RELAY_TICKET_JTI.test(jti) || !/^[0-9]{1,12}$/.test(expText)) {
    return null;
  }
  const exp = Number.parseInt(expText, 10);
  if (!Number.isSafeInteger(exp) || exp <= 0) {
    return null;
  }
  return { jti, exp };
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

export async function consumeAgentAdmission(
  storage,
  admissionJti,
  admissionExpSeconds,
  relayTicketJti = null,
  relayTicketExpSeconds = null,
  nowMS = Date.now(),
) {
  if (
    !UUID.test(admissionJti) ||
    !Number.isSafeInteger(admissionExpSeconds) ||
    admissionExpSeconds <= 0 ||
    !Number.isSafeInteger(nowMS) ||
    ((relayTicketJti === null) !== (relayTicketExpSeconds === null)) ||
    (relayTicketJti !== null && (!RELAY_TICKET_JTI.test(relayTicketJti) || !Number.isSafeInteger(relayTicketExpSeconds) || relayTicketExpSeconds <= 0))
  ) {
    throw new Error("invalid agent admission replay metadata");
  }

  const entries = [{
    key: AGENT_ADMISSION_STORAGE_PREFIX + admissionJti.toLowerCase(),
    expiresAtMS: admissionExpSeconds * 1000 + CLOCK_SKEW_MS,
  }];
  if (relayTicketJti !== null) {
    entries.push({
      key: RELAY_TICKET_STORAGE_PREFIX + relayTicketJti,
      expiresAtMS: relayTicketExpSeconds * 1000 + CLOCK_SKEW_MS,
    });
  }
  if (entries.some((entry) => !Number.isSafeInteger(entry.expiresAtMS) || entry.expiresAtMS < nowMS)) {
    return { accepted: false, expiresAtMS: Math.min(...entries.map((entry) => entry.expiresAtMS)) };
  }

  const accepted = await storage.transaction(async (txn) => {
    for (const entry of entries) {
      if (await txn.get(entry.key) !== undefined) return false;
    }
    for (const entry of entries) {
      await txn.put(entry.key, entry.expiresAtMS);
    }
    return true;
  });

  return { accepted, expiresAtMS: Math.min(...entries.map((entry) => entry.expiresAtMS)) };
}

export async function scheduleReplayCleanup(storage, expiresAtMS) {
  const current = await storage.getAlarm();
  if (current === null || expiresAtMS < current) {
    await storage.setAlarm(expiresAtMS);
  }
}

export async function cleanupExpiredConnectionGrants(storage, nowMS = Date.now()) {
  const prefixes = [STORAGE_PREFIX, AGENT_ADMISSION_STORAGE_PREFIX, RELAY_TICKET_STORAGE_PREFIX];
  let nextAlarm = null;

  for (const prefix of prefixes) {
    const entries = await storage.list({ prefix });
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
  }

  if (nextAlarm !== null) {
    await storage.setAlarm(nextAlarm);
  }
}
