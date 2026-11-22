export const MAX_AGENT_SESSION_LIFETIME_MS = 12 * 60 * 60 * 1000;
export const AGENT_SESSION_IDLE_TIMEOUT_MS = 15 * 60 * 1000;

export function createAgentSessionAttachment(attachment, nowMS = Date.now()) {
  if (
    attachment === null ||
    typeof attachment !== "object" ||
    attachment.role !== "agent" ||
    !Number.isSafeInteger(nowMS) ||
    nowMS < 0
  ) {
    throw new Error("invalid agent session attachment");
  }
  const absoluteExpiresAtMS = attachment.absoluteExpiresAtMS ?? nowMS + MAX_AGENT_SESSION_LIFETIME_MS;
  if (
    !Number.isSafeInteger(absoluteExpiresAtMS) ||
    absoluteExpiresAtMS <= nowMS ||
    absoluteExpiresAtMS > nowMS + MAX_AGENT_SESSION_LIFETIME_MS
  ) {
    throw new Error("invalid agent session absolute expiry");
  }
  return {
    ...attachment,
    createdAtMS: nowMS,
    lastActivityAtMS: nowMS,
    absoluteExpiresAtMS,
  };
}

export function agentSessionExpired(attachment, nowMS = Date.now()) {
  if (
    attachment === null ||
    typeof attachment !== "object" ||
    attachment.role !== "agent" ||
    !Number.isSafeInteger(nowMS) ||
    nowMS < 0 ||
    !Number.isSafeInteger(attachment.createdAtMS) ||
    attachment.createdAtMS < 0 ||
    !Number.isSafeInteger(attachment.lastActivityAtMS) ||
    attachment.lastActivityAtMS < attachment.createdAtMS ||
    attachment.lastActivityAtMS > nowMS
  ) {
    return true;
  }
  const absoluteExpiresAtMS = attachment.absoluteExpiresAtMS ?? attachment.createdAtMS + MAX_AGENT_SESSION_LIFETIME_MS;
  if (!Number.isSafeInteger(absoluteExpiresAtMS) || absoluteExpiresAtMS <= attachment.createdAtMS) {
    return true;
  }
  return (
    nowMS >= absoluteExpiresAtMS ||
    nowMS >= attachment.lastActivityAtMS + AGENT_SESSION_IDLE_TIMEOUT_MS
  );
}

export function touchAgentSessionAttachment(attachment, nowMS = Date.now()) {
  if (agentSessionExpired(attachment, nowMS)) {
    return null;
  }
  return { ...attachment, lastActivityAtMS: nowMS };
}

export function nextAgentSessionExpiry(entries, nowMS = Date.now()) {
  if (!Array.isArray(entries) || !Number.isSafeInteger(nowMS) || nowMS < 0) {
    throw new Error("invalid agent session expiry input");
  }
  let next = null;
  for (const entry of entries) {
    if (entry?.readyState !== 1) continue;
    const attachment = entry.attachment;
    if (attachment?.role !== "agent") continue;
    if (agentSessionExpired(attachment, nowMS)) return nowMS;
    const absoluteExpiresAtMS = attachment.absoluteExpiresAtMS ?? attachment.createdAtMS + MAX_AGENT_SESSION_LIFETIME_MS;
    const expiry = Math.min(
      absoluteExpiresAtMS,
      attachment.lastActivityAtMS + AGENT_SESSION_IDLE_TIMEOUT_MS,
    );
    if (next === null || expiry < next) next = expiry;
  }
  return next;
}
