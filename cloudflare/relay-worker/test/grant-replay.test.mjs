import assert from "node:assert/strict";
import test from "node:test";

import {
  cleanupExpiredConnectionGrants,
  consumeConnectionGrant,
  INTERNAL_GRANT_CLIENT_HEADER,
  INTERNAL_GRANT_EXP_HEADER,
  INTERNAL_GRANT_FLOW_HEADER,
  INTERNAL_GRANT_ID_HEADER,
  INTERNAL_GRANT_JTI_HEADER,
  INTERNAL_GRANT_PERMISSION_HEADER,
  INTERNAL_GRANT_TARGET_HEADER,
  INTERNAL_GRANT_VALIDATED_AT_HEADER,
  INTERNAL_GRANT_RUN_ID_HEADER,
  INTERNAL_GRANT_VALIDATION_ATTEMPT_HEADER,
  prepareDeviceRelayRequest,
  readConnectionGrantEvent,
  readConnectionGrantEvidence,
  replayMetadataFromRequest,
  scheduleReplayCleanup,
} from "../src/grant-replay.js";

const jti = "76b4c468-4e39-437c-a9c8-b758c92ab89b";
const grantID = "d90987bf-bae6-45da-ab21-c82d049617bd";
const clientDeviceID = "wd_aaaaaaaaaaaaaaaa";
const targetDeviceID = "wd_bbbbbbbbbbbbbbbb";
const authorizationRunID = "d90987bf-bae6-45da-ab21-c82d049617bd";
const validationAttemptID = "b90987bf-bae6-45da-ab21-c82d049617bd";
const nowMS = 1_800_000_000_000;
const exp = 1_800_000_090;

function replay(flow = "direct", override = {}) {
  return {
    jti, exp, grantID, clientDeviceID, targetDeviceID, flow,
    permission: "terminal.connect",
    validatedAtMS: nowMS,
    authorizationRunID,
    validationAttemptID,
    ...override,
  };
}

function requestFor(metadata) {
  return new Request("https://relay.test/v1/authorize", {
    headers: {
      [INTERNAL_GRANT_JTI_HEADER]: metadata.jti,
      [INTERNAL_GRANT_EXP_HEADER]: String(metadata.exp),
      [INTERNAL_GRANT_ID_HEADER]: metadata.grantID,
      [INTERNAL_GRANT_CLIENT_HEADER]: metadata.clientDeviceID,
      [INTERNAL_GRANT_TARGET_HEADER]: metadata.targetDeviceID,
      [INTERNAL_GRANT_FLOW_HEADER]: metadata.flow,
      [INTERNAL_GRANT_PERMISSION_HEADER]: metadata.permission,
      [INTERNAL_GRANT_VALIDATED_AT_HEADER]: String(metadata.validatedAtMS),
      [INTERNAL_GRANT_RUN_ID_HEADER]: metadata.authorizationRunID,
      [INTERNAL_GRANT_VALIDATION_ATTEMPT_HEADER]: metadata.validationAttemptID,
    },
  });
}

class MemoryStorage {
  constructor() {
    this.data = new Map();
    this.alarm = null;
    this.lock = Promise.resolve();
  }
  async transaction(fn) {
    let release;
    const previous = this.lock;
    this.lock = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      return await fn({
        get: async (key) => this.data.get(key),
        put: async (key, value) => { this.data.set(key, value); },
      });
    } finally {
      release();
    }
  }
  async get(key) { return this.data.get(key); }
  async getAlarm() { return this.alarm; }
  async setAlarm(value) { this.alarm = value; }
  async list({ prefix }) { return new Map([...this.data].filter(([key]) => key.startsWith(prefix))); }
  async delete(key) { return this.data.delete(key); }
}

test("parses only complete, server-generated replay metadata", () => {
  assert.deepEqual(replayMetadataFromRequest(requestFor(replay())), replay());
  const missing = new Request("https://relay.test", {
    headers: { [INTERNAL_GRANT_JTI_HEADER]: jti, [INTERNAL_GRANT_EXP_HEADER]: String(exp) },
  });
  assert.equal(replayMetadataFromRequest(missing), null);
  assert.equal(replayMetadataFromRequest(requestFor(replay("unknown"))), null);
  assert.equal(replayMetadataFromRequest(requestFor(replay("direct", { authorizationRunID: "" }))), null);
  assert.equal(replayMetadataFromRequest(requestFor(replay("direct", { validationAttemptID: "bad" }))), null);
});

test("sanitizes client-supplied replay metadata before Durable Object forwarding", () => {
  const req = new Request("https://relay.test/v1/stream/wd_bbbbbbbbbbbbbbbb?role=client", {
    headers: {
      Authorization: "Bearer secret-ticket",
      "X-WeDecent-Connection-Grant": "secret-grant",
      [INTERNAL_GRANT_JTI_HEADER]: "d90987bf-bae6-45da-ab21-c82d049617bd",
      [INTERNAL_GRANT_EXP_HEADER]: "1",
      [INTERNAL_GRANT_ID_HEADER]: "d90987bf-bae6-45da-ab21-c82d049617bd",
      Upgrade: "websocket",
    },
  });
  const forwarded = prepareDeviceRelayRequest(req, replay("relay"), "X-WeDecent-Connection-Grant");
  assert.equal(forwarded.headers.get("Authorization"), null);
  assert.equal(forwarded.headers.get("X-WeDecent-Connection-Grant"), null);
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_JTI_HEADER), jti);
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_EXP_HEADER), String(exp));
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_ID_HEADER), grantID);
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_CLIENT_HEADER), clientDeviceID);
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_TARGET_HEADER), targetDeviceID);
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_FLOW_HEADER), "relay");
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_PERMISSION_HEADER), "terminal.connect");
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_VALIDATED_AT_HEADER), String(nowMS));
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_RUN_ID_HEADER), authorizationRunID);
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_VALIDATION_ATTEMPT_HEADER), validationAttemptID);
  assert.equal(forwarded.headers.get("Upgrade"), "websocket");
});

test("consumes a grant once and stores independently retrievable server evidence", async () => {
  const storage = new MemoryStorage();
  const first = await consumeConnectionGrant(storage, replay(), nowMS);
  const second = await consumeConnectionGrant(storage, replay(), nowMS + 1);
  assert.equal(first.accepted, true);
  assert.equal(second.accepted, false);
  const evidence = await readConnectionGrantEvidence(storage, jti, targetDeviceID);
  assert.equal(evidence.validation_outcome, "accepted");
  assert.equal(evidence.consumption_outcome, "consumed");
  assert.equal(evidence.flow, "direct");
  assert.equal(evidence.jti, jti);
  assert.equal(evidence.authorization_run_id, authorizationRunID);
  assert.equal(evidence.validation_attempt_id, validationAttemptID);
  assert.match(evidence.consumption_attempt_id, /^[0-9a-f-]{36}$/);
  assert.notEqual(evidence.validation_attempt_id, evidence.consumption_attempt_id);
  assert.notEqual(evidence.validation_event_id, evidence.consumption_event_id);
  assert.equal(evidence.validation_event.type, "authorization.validation");
  assert.equal(evidence.validation_event.outcome, "accepted");
  assert.equal(evidence.consumption_event.type, "authorization.consumption");
  assert.equal(evidence.consumption_event.outcome, "consumed");
  assert.deepEqual(await readConnectionGrantEvent(storage, evidence.validation_event_id), evidence.validation_event);
  assert.deepEqual(await readConnectionGrantEvent(storage, evidence.consumption_event_id), evidence.consumption_event);
  const otherTargetStorage = new MemoryStorage();
  assert.equal(await readConnectionGrantEvidence(otherTargetStorage, jti), null);
});

test("simultaneous consumption has exactly one winner and one evidence record", async () => {
  const storage = new MemoryStorage();
  const results = await Promise.all(Array.from({ length: 8 }, () => consumeConnectionGrant(storage, replay("relay"), nowMS)));
  assert.equal(results.filter((result) => result.accepted).length, 1);
  const evidence = await readConnectionGrantEvidence(storage, jti, targetDeviceID);
  assert.equal(evidence.flow, "relay");
});

test("different grant identifiers are independently accepted", async () => {
  const storage = new MemoryStorage();
  const first = await consumeConnectionGrant(storage, replay(), nowMS);
  const second = await consumeConnectionGrant(storage, replay("relay", {
    jti: "d90987bf-bae6-45da-ab21-c82d049617bd",
    grantID: "b90987bf-bae6-45da-ab21-c82d049617bd",
  }), nowMS);
  assert.equal(first.accepted, true);
  assert.equal(second.accepted, true);
});

test("expired or stale validation metadata cannot be consumed", async () => {
  const storage = new MemoryStorage();
  const expired = await consumeConnectionGrant(storage, replay("direct", { exp: 1_799_999_900 }), nowMS);
  assert.equal(expired.accepted, false);
  const stale = await consumeConnectionGrant(storage, replay("direct", { validatedAtMS: nowMS - 31_000 }), nowMS);
  assert.equal(stale.accepted, false);
});

test("cleanup removes replay locks at expiry and evidence after its retention period", async () => {
  const storage = new MemoryStorage();
  const first = await consumeConnectionGrant(storage, replay(), nowMS);
  const anotherJTI = "d90987bf-bae6-45da-ab21-c82d049617bd";
  const second = await consumeConnectionGrant(storage, replay("relay", {
    jti: anotherJTI,
    grantID: "b90987bf-bae6-45da-ab21-c82d049617bd",
    exp: exp + 60,
  }), nowMS);
  await scheduleReplayCleanup(storage, first.expiresAtMS);
  await cleanupExpiredConnectionGrants(storage, first.expiresAtMS + 1);
  assert.equal(storage.data.has("connection-grant-jti:" + jti), false);
  assert.equal(storage.data.has("connection-grant-evidence:" + jti), true);
  assert.equal(storage.alarm, second.expiresAtMS);

  await cleanupExpiredConnectionGrants(storage, second.expiresAtMS + 1);
  assert.equal(storage.data.has("connection-grant-jti:" + anotherJTI), false);
  assert.ok(storage.data.has("connection-grant-evidence:" + anotherJTI));
  await cleanupExpiredConnectionGrants(storage, first.evidence.retain_until_ms + 1);
  assert.equal(storage.data.has("connection-grant-evidence:" + jti), false);
  assert.equal(storage.data.has("connection-grant-evidence:" + anotherJTI), false);
});
