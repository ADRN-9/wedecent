import { verifyAgentAdmission, verifyConnectionGrant } from "./connection-grant.js";
import { verifyRelayTicket } from "./relay-auth.js";

export const CONNECTION_GRANT_HEADER = "X-WeDecent-Connection-Grant";
export const AGENT_ADMISSION_HEADER = "X-WeDecent-Agent-Admission";

export async function authorizeStream(request, env, expected, nowSeconds = Math.floor(Date.now() / 1000)) {
  const token = bearerToken(request);
  if (!token) {
    return { ok: false, status: 401, message: "Unauthorized" };
  }

  if (token.startsWith("wdt2.")) {
    let relayClaims;
    try {
      relayClaims = await verifyRelayTicket(token, expected, nowSeconds);
    } catch {
      return { ok: false, status: 401, message: "Unauthorized" };
    }

    if (expected.role === "agent") {
      const admission = await verifyAgentAdmissionHeader(request, env, expected, nowSeconds);
      if (!admission.ok) return admission;
      return {
        ok: true,
        deviceID: relayClaims.iss,
        targetDeviceID: relayClaims.sub,
        agentAdmissionReplay: admission.replay,
        relayTicketReplay: { jti: relayClaims.jti, exp: relayClaims.exp },
      };
    }

    const grant = request.headers.get(CONNECTION_GRANT_HEADER)?.trim();
    if (!grant) {
      return { ok: false, status: 403, message: "Connection grant required" };
    }
    if (!env.WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64) {
      return { ok: false, status: 503, message: "Connection grant verifier is not configured" };
    }
    const clientDeviceID = expected.role === "authorize" ? expected.clientDeviceID : relayClaims.iss;
    if (expected.role === "authorize" && (typeof clientDeviceID !== "string" || clientDeviceID.length === 0)) {
      return { ok: false, status: 403, message: "Connection grant rejected" };
    }
    try {
      const grantClaims = await verifyConnectionGrant(
        grant,
        {
          clientDeviceID,
          targetDeviceID: expected.deviceId,
          permission: "terminal.connect",
        },
        env.WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64,
        nowSeconds,
      );
      return {
        ok: true,
        deviceID: grantClaims.client_device_id,
        targetDeviceID: grantClaims.target_device_id,
        replay: { jti: grantClaims.jti, exp: grantClaims.exp },
      };
    } catch {
      return { ok: false, status: 403, message: "Connection grant rejected" };
    }
  }

  // The shared relay token remains a migration credential, not an enrollment authority.
  if (expected.role === "agent" && env.RELAY_ACCESS_TOKEN && token === env.RELAY_ACCESS_TOKEN) {
    const admission = await verifyAgentAdmissionHeader(request, env, expected, nowSeconds);
    if (!admission.ok) return admission;
    return {
      ok: true,
      deviceID: admission.deviceID,
      targetDeviceID: admission.deviceID,
      legacy: true,
      agentAdmissionReplay: admission.replay,
    };
  }

  return { ok: false, status: 401, message: "Unauthorized" };
}

async function verifyAgentAdmissionHeader(request, env, expected, nowSeconds) {
  const token = request.headers.get(AGENT_ADMISSION_HEADER)?.trim() ?? "";
  if (!token) {
    return { ok: false, status: 403, message: "Agent enrollment required" };
  }
  const publicKey = env.WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64;
  if (!publicKey) {
    return { ok: false, status: 503, message: "Agent admission verifier is not configured" };
  }
  try {
    const claims = await verifyAgentAdmission(
      token,
      { targetDeviceID: expected.deviceId, slot: expected.slot },
      publicKey,
      nowSeconds,
    );
    return {
      ok: true,
      deviceID: claims.target_device_id,
      replay: { jti: claims.jti, exp: claims.exp },
    };
  } catch {
    return { ok: false, status: 403, message: "Agent admission rejected" };
  }
}

function bearerToken(request) {
  const value = request.headers.get("Authorization");
  if (!value) return "";
  const match = /^Bearer ([^\s]+)$/.exec(value);
  return match ? match[1] : "";
}
