const DEVICE_ID = /^wd_[a-z2-7]{16}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TOKEN = /^[A-Za-z0-9_-]{43,128}$/;

export function relayRevocationOrigin(rawURL) {
  let endpoint;
  try {
    endpoint = new URL(String(rawURL ?? ""));
  } catch {
    throw new Error("relay_endpoint_invalid");
  }
  if (
    endpoint.protocol !== "https:" ||
    !endpoint.hostname ||
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    endpoint.pathname !== "/" ||
    endpoint.search !== "" ||
    endpoint.hash !== ""
  ) {
    throw new Error("relay_endpoint_invalid");
  }
  return endpoint.origin;
}

export async function dispatchPendingDeviceRevocations(admin, options = {}) {
  if (!admin || typeof admin.rpc !== "function") throw new Error("revocation_dispatch_admin_invalid");
  const limit = options.limit ?? 20;
  const deviceID = options.deviceID ?? null;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
      (deviceID !== null && (typeof deviceID !== "string" || !DEVICE_ID.test(deviceID)))) {
    throw new Error("revocation_dispatch_scope_invalid");
  }

  const { data: claimed, error: claimError } = await admin.rpc("claim_device_revocation_dispatches", {
    p_limit: limit,
    p_lease_seconds: 60,
    p_device_id: deviceID,
  });
  if (claimError) throw new Error("revocation_dispatch_claim_unavailable");
  if (!Array.isArray(claimed)) throw new Error("revocation_dispatch_claim_invalid");

  let origin = "";
  let configurationError = null;
  const relayToken = String(options.relayToken ?? "");
  try {
    if (!TOKEN.test(relayToken)) throw new Error("relay_configuration_missing");
    origin = relayRevocationOrigin(options.relayURL);
  } catch (error) {
    configurationError = error instanceof Error && error.message === "relay_endpoint_invalid"
      ? "relay_endpoint_invalid"
      : "relay_configuration_missing";
  }

  const fetchImpl = options.fetchImpl ?? fetch;
  let dispatched = 0;
  let failed = 0;
  let staleAcknowledgements = 0;
  let authorizationGeneration = null;

  for (const event of claimed) {
    if (
      event === null ||
      typeof event !== "object" ||
      !UUID.test(String(event.id ?? "")) ||
      !UUID.test(String(event.claim_token ?? "")) ||
      typeof event.device_id !== "string" ||
      !DEVICE_ID.test(event.device_id) ||
      !Number.isSafeInteger(event.authorization_generation) ||
      event.authorization_generation < 1
    ) {
      throw new Error("revocation_dispatch_claim_invalid");
    }
    authorizationGeneration = event.authorization_generation;
    let failureCode = configurationError;
    if (!failureCode) {
      try {
        const endpoint = new URL(
          "/v1/revoke/" + encodeURIComponent(event.device_id),
          origin,
        );
        endpoint.searchParams.set("generation", String(event.authorization_generation));
        const response = await fetchImpl(endpoint, {
          method: "POST",
          headers: {
            Authorization: "Bearer " + relayToken,
            "Cache-Control": "no-store",
          },
          redirect: "error",
          signal: AbortSignal.timeout(10_000),
        });
        if (!response.ok) failureCode = "relay_dispatch_failed";
      } catch {
        failureCode = "relay_dispatch_failed";
      }
    }

    if (failureCode) {
      const { data: recorded, error: failureError } = await admin.rpc("fail_device_revocation_dispatch", {
        p_id: event.id,
        p_claim_token: event.claim_token,
        p_authorization_generation: event.authorization_generation,
        p_error_code: failureCode,
      });
      if (failureError) throw new Error("revocation_dispatch_failure_ack_unavailable");
      if (recorded === true) failed += 1;
      else staleAcknowledgements += 1;
      continue;
    }

    const { data: completed, error: completionError } = await admin.rpc("complete_device_revocation_dispatch", {
      p_id: event.id,
      p_claim_token: event.claim_token,
      p_authorization_generation: event.authorization_generation,
    });
    if (completionError) throw new Error("revocation_dispatch_completion_unavailable");
    if (completed === true) dispatched += 1;
    else staleAcknowledgements += 1;
  }

  return {
    claimed: claimed.length,
    dispatched,
    failed,
    staleAcknowledgements,
    authorizationGeneration,
  };
}
