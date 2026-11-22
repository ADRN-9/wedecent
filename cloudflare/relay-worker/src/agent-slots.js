export const MAX_AGENT_CONNECTIONS = 32;
const OPEN_READY_STATE = 1;

export function planAgentSlotAdmission(entries, slot, maximum = MAX_AGENT_CONNECTIONS) {
  if (!Number.isSafeInteger(slot) || slot < 1 || slot > MAX_AGENT_CONNECTIONS) {
    return { ok: false, status: 400, retire: [] };
  }
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > MAX_AGENT_CONNECTIONS) {
    throw new Error("invalid agent connection limit");
  }

  const open = entries.filter((entry) => entry?.readyState === OPEN_READY_STATE);
  const duplicateActiveSlot = open.some((entry) => {
    const attachment = entry.attachment;
    return attachment?.role === "agent" && attachment.slot === slot && Boolean(attachment.peerId);
  });
  if (duplicateActiveSlot) {
    return { ok: false, status: 409, retire: [] };
  }

  const retire = open.filter((entry) => {
    const attachment = entry.attachment;
    if (attachment?.role !== "agent" || attachment.peerId) return false;
    return !Number.isSafeInteger(attachment.slot) || attachment.slot === slot;
  });

  if (open.length - retire.length >= maximum) {
    return { ok: false, status: 429, retire: [] };
  }
  return { ok: true, status: 101, retire };
}
