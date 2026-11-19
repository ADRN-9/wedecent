import assert from "node:assert/strict";
import test from "node:test";

import { consumeRelayAdmission, readRelayGrantEvidence } from "../src/relay-admission.js";
import { prepareDeviceRelayRequest } from "../src/grant-replay.js";

const nowMS = 1_800_000_000_000;
const jti = "76b4c468-4e39-437c-a9c8-b758c92ab89b";
const grantID = "d90987bf-bae6-45da-ab21-c82d049617bd";
const clientDeviceID = "wd_aaaaaaaaaaaaaaaa";
const targetDeviceID = "wd_bbbbbbbbbbbbbbbb";

function admissionRequest(flow = "relay", override = {}) {
  const replay = {
    jti,
    exp: 1_800_000_090,
    grantID,
    clientDeviceID,
    targetDeviceID,
    flow,
    permission: "terminal.connect",
    validatedAtMS: nowMS,
    authorizationRunID: "d90987bf-bae6-45da-ab21-c82d049617bd",
    validationAttemptID: "b90987bf-bae6-45da-ab21-c82d049617bd",
    ...override,
  };
  const outer = new Request("https://relay.test/v1/stream/" + targetDeviceID + "?role=client", {
    headers: { Authorization: "Bearer untrusted", "X-WeDecent-Connection-Grant": "untrusted" },
  });
  return prepareDeviceRelayRequest(outer, replay, "X-WeDecent-Connection-Grant");
}

class DurableObjectStorageFixture {
  constructor() {
    this.values = new Map();
    this.alarm = null;
    this.lock = Promise.resolve();
  }

  async transaction(callback) {
    let release;
    const previous = this.lock;
    this.lock = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      return await callback({
        get: async (key) => this.values.get(key),
        put: async (key, value) => { this.values.set(key, value); },
      });
    } finally {
      release();
    }
  }

  async get(key) { return this.values.get(key); }
  async getAlarm() { return this.alarm; }
  async setAlarm(value) { this.alarm = value; }
}

test("relay admission consumes once and exposes the server evidence", async () => {
  const storage = new DurableObjectStorageFixture();
  const request = admissionRequest("relay");

  const admitted = await consumeRelayAdmission(storage, request, nowMS);
  assert.equal(admitted.accepted, true);
  assert.equal(admitted.evidence.flow, "relay");

  const evidence = await readRelayGrantEvidence(storage, jti);
  assert.deepEqual(evidence, admitted.evidence);
  assert.equal(evidence.validation_outcome, "accepted");
  assert.equal(evidence.consumption_outcome, "consumed");
  assert.equal(evidence.client_device_id, clientDeviceID);
  assert.equal(evidence.target_device_id, targetDeviceID);
  assert.equal(storage.alarm, 1_800_000_120_000);

  const replayed = await consumeRelayAdmission(storage, request, nowMS + 1);
  assert.deepEqual(replayed, {
    accepted: false,
    status: 409,
    message: "Connection grant already used",
  });
  assert.deepEqual(await readRelayGrantEvidence(storage, jti), evidence);
});

test("direct authorization and relay admission share the same replay lock", async () => {
  for (const firstFlow of ["direct", "relay"]) {
    const storage = new DurableObjectStorageFixture();
    const first = await consumeRelayAdmission(storage, admissionRequest(firstFlow), nowMS);
    const secondFlow = firstFlow === "direct" ? "relay" : "direct";
    const second = await consumeRelayAdmission(storage, admissionRequest(secondFlow), nowMS + 1);
    assert.equal(first.accepted, true);
    assert.equal(second.accepted, false);
    assert.equal(second.status, 409);
    assert.equal((await readRelayGrantEvidence(storage, jti)).flow, firstFlow);
  }
});

test("relay admission rejects missing, stale, and expired grants without evidence", async () => {
  const storage = new DurableObjectStorageFixture();
  const missing = new Request("https://relay.test/v1/stream/" + targetDeviceID + "?role=client");
  assert.equal((await consumeRelayAdmission(storage, missing, nowMS)).status, 403);

  const stale = await consumeRelayAdmission(storage, admissionRequest("relay", {
    validatedAtMS: nowMS - 31_000,
  }), nowMS);
  assert.equal(stale.status, 403);

  const expired = await consumeRelayAdmission(storage, admissionRequest("relay", {
    exp: 1_799_999_900,
  }), nowMS);
  assert.equal(expired.status, 403);
  assert.equal(await readRelayGrantEvidence(storage, jti), null);
});
