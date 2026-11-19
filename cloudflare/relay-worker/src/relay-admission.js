import {
  consumeConnectionGrant,
  readConnectionGrantEvidence,
  replayMetadataFromRequest,
  scheduleReplayCleanup,
} from "./grant-replay.js";

export async function consumeRelayAdmission(storage, request, nowMS = Date.now()) {
  const replay = replayMetadataFromRequest(request);
  if (!replay) {
    return { accepted: false, status: 403, message: "Connection grant replay metadata missing" };
  }

  const consumption = await consumeConnectionGrant(storage, replay, nowMS);
  if (!consumption.accepted) {
    if (consumption.reason === "replay") {
      return { accepted: false, status: 409, message: "Connection grant already used" };
    }
    return { accepted: false, status: 403, message: "Connection grant is expired or stale" };
  }

  await scheduleReplayCleanup(storage, consumption.expiresAtMS);
  return { accepted: true, evidence: consumption.evidence };
}

export async function readRelayGrantEvidence(storage, jti) {
  return readConnectionGrantEvidence(storage, jti);
}
