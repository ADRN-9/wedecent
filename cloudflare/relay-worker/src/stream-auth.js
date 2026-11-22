import { verifyAgentAdmission, verifyConnectionGrant } from "./connection-grant.js";
import { devicePublicKeyFingerprint, verifyRelayTicket } from "./relay-auth.js";

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
      let publicKeyFingerprint;
      try {
        publicKeyFingerprint = await devicePublicKeyFingerprint(relayClaims.pk);
      } catch {
        return { ok: false, status: 401, message: "Unauthorized" };
      }
      const admission = await verifyAgentAdmissionHeader(
        request,
        env,
        { deviceID: relayClaims.iss, publicKeyFingerprint, slot: expected.slot },
        nowSeconds,
      );
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

  return { ok: false, status: 401, message: "Unauthorized" };
}

async function verifyAgentAdmissionHeader(request, env, expected, nowSeconds) {
  const token = request.headers.get(AGENT_ADMISSION_HEADER)?.trim() ?? "";
  if (!token) {
    return { ok: false, status: 403, message: "Agent enrollment required" };
  }
  const keyring = env.WEDECENT_AGENT_ADMISSION_PUBLIC_KEYS_JSON;
  if (!keyring || !env.WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64) {
    return { ok: false, status: 503, message: "Agent admission verifier is not configured" };
  }
  try {
    const claims = await verifyAgentAdmission(token, expected, keyring, nowSeconds, env.WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64);
    return {
      ok: true,
      deviceID: claims.device_id,
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
