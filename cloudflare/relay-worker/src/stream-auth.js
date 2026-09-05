import { verifyConnectionGrant } from "./connection-grant.js";
import { verifyRelayTicket } from "./relay-auth.js";

export const CONNECTION_GRANT_HEADER = "X-WeDecent-Connection-Grant";

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
      return { ok: true };
    }

    const grant = request.headers.get(CONNECTION_GRANT_HEADER)?.trim();
    if (!grant) {
      return { ok: false, status: 403, message: "Connection grant required" };
    }
    if (!env.WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64) {
      return { ok: false, status: 503, message: "Connection grant verifier is not configured" };
    }
    try {
      const grantClaims = await verifyConnectionGrant(
        grant,
        {
          clientDeviceID: relayClaims.iss,
          targetDeviceID: expected.deviceId,
          permission: "terminal.connect",
        },
        env.WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64,
        nowSeconds,
      );
      return { ok: true, replay: { jti: grantClaims.jti, exp: grantClaims.exp } };
    } catch {
      return { ok: false, status: 403, message: "Connection grant rejected" };
    }
  }

  // The shared relay token remains only as an agent migration credential.
  // Allowing it for clients would bypass account-scoped connection grants.
  if (expected.role === "agent" && env.RELAY_ACCESS_TOKEN && token === env.RELAY_ACCESS_TOKEN) {
    return { ok: true };
  }
  return { ok: false, status: 401, message: "Unauthorized" };
}

function bearerToken(request) {
  const value = request.headers.get("Authorization");
  if (!value) return "";
  const match = /^Bearer ([^\s]+)$/.exec(value);
  return match ? match[1] : "";
}
