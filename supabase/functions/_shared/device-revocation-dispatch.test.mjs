import test from "node:test";
import assert from "node:assert/strict";
import {
  dispatchPendingDeviceRevocations,
  relayRevocationOrigin,
} from "./device-revocation-dispatch.mjs";

const event = {
  id: "10000000-0000-4000-8000-000000000101",
  claim_token: "10000000-0000-4000-8000-000000000102",
  device_id: "wd_aaaaaaaaaaaaaaaa",
  authorization_generation: 7,
};

function adminFor(claimHandler, completeHandler, failHandler = async () => ({ data: true, error: null })) {
  return {
    async rpc(name, args) {
      if (name === "claim_device_revocation_dispatches") return claimHandler(args);
      if (name === "complete_device_revocation_dispatch") return completeHandler(args);
      if (name === "fail_device_revocation_dispatch") return failHandler(args);
      throw new Error("unexpected RPC " + name);
    },
  };
}

test("relay endpoint requires an HTTPS origin without URL decorations", () => {
  assert.equal(relayRevocationOrigin("https://relay.wedecent.com"), "https://relay.wedecent.com");
  for (const value of [
    "http://relay.wedecent.com",
    "https://user:secret@relay.wedecent.com",
    "https://relay.wedecent.com/path",
    "https://relay.wedecent.com/?redirect=https://evil.example",
    "https://relay.wedecent.com/#fragment",
  ]) {
    assert.throws(() => relayRevocationOrigin(value), /relay_endpoint_invalid/);
  }
});

test("duplicate scheduled delivery claims an outbox event once", async () => {
  let pending = true;
  let claimed = false;
  let fetchCount = 0;
  const admin = adminFor(
    async () => {
      if (!pending || claimed) return { data: [], error: null };
      claimed = true;
      return { data: [event], error: null };
    },
    async () => {
      pending = false;
      return { data: true, error: null };
    },
  );
  const options = {
    relayURL: "https://relay.wedecent",
    relayToken: "A".repeat(43),
    fetchImpl: async (url, init) => {
      fetchCount++;
      assert.equal(new URL(url).searchParams.get("generation"), "7");
      assert.equal(init.redirect, "error");
      return new Response(null, { status: 204 });
    },
  };
  const first = await dispatchPendingDeviceRevocations(admin, options);
  const second = await dispatchPendingDeviceRevocations(admin, options);
  assert.equal(first.dispatched, 1);
  assert.equal(second.claimed, 0);
  assert.equal(fetchCount, 1);
});

test("stale acknowledgement does not mark a reclaimed event complete", async () => {
  const admin = adminFor(
    async () => ({ data: [event], error: null }),
    async () => ({ data: false, error: null }),
  );
  const result = await dispatchPendingDeviceRevocations(admin, {
    relayURL: "https://relay.wedecent",
    relayToken: "B".repeat(43),
    fetchImpl: async () => new Response(null, { status: 204 }),
  });
  assert.equal(result.dispatched, 0);
  assert.equal(result.staleAcknowledgements, 1);
});

test("relay failure records bounded retry state without exposing response text", async () => {
  let failureArgs = null;
  const admin = adminFor(
    async () => ({ data: [event], error: null }),
    async () => ({ data: false, error: null }),
    async (args) => {
      failureArgs = args;
      return { data: true, error: null };
    },
  );
  const result = await dispatchPendingDeviceRevocations(admin, {
    relayURL: "https://relay.wedecent",
    relayToken: "C".repeat(43),
    fetchImpl: async () => new Response("sensitive relay body", { status: 503 }),
  });
  assert.equal(result.failed, 1);
  assert.equal(failureArgs.p_error_code, "relay_dispatch_failed");
  assert.equal(JSON.stringify(failureArgs).includes("sensitive"), false);
});

test("missing relay credentials fail closed and leave the event retryable", async () => {
  let failureArgs = null;
  const admin = adminFor(
    async () => ({ data: [event], error: null }),
    async () => ({ data: false, error: null }),
    async (args) => {
      failureArgs = args;
      return { data: true, error: null };
    },
  );
  const result = await dispatchPendingDeviceRevocations(admin, {
    relayURL: "http://relay.wedecent",
    relayToken: "",
    fetchImpl: async () => {
      throw new Error("must not fetch an insecure endpoint");
    },
  });
  assert.equal(result.failed, 1);
  assert.equal(failureArgs.p_error_code, "relay_configuration_missing");
});
