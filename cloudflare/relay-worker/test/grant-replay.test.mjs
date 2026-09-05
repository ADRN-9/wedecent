import assert from "node:assert/strict";
import test from "node:test";

import {
  cleanupExpiredConnectionGrants,
  consumeConnectionGrant,
  INTERNAL_GRANT_EXP_HEADER,
  INTERNAL_GRANT_JTI_HEADER,
  prepareDeviceRelayRequest,
  replayMetadataFromRequest,
  scheduleReplayCleanup,
} from "../src/grant-replay.js";

const jti = "76b4c468-4e39-437c-a9c8-b758c92ab89b";
const nowMS = 1_800_000_000_000;
const exp = 1_800_000_090;

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

  async getAlarm() { return this.alarm; }
  async setAlarm(value) { this.alarm = value; }
  async list({ prefix }) {
    return new Map([...this.data].filter(([key]) => key.startsWith(prefix)));
  }
  async delete(key) { return this.data.delete(key); }
}

test("parses only well-formed trusted replay metadata", () => {
  const req = new Request("https://relay.test", {
    headers: {
      [INTERNAL_GRANT_JTI_HEADER]: jti,
      [INTERNAL_GRANT_EXP_HEADER]: String(exp),
    },
  });
  assert.deepEqual(replayMetadataFromRequest(req), { jti, exp });

  const bad = new Request("https://relay.test", {
    headers: { [INTERNAL_GRANT_JTI_HEADER]: "not-a-jti", [INTERNAL_GRANT_EXP_HEADER]: String(exp) },
  });
  assert.equal(replayMetadataFromRequest(bad), null);
});


test("sanitizes client-supplied internal replay headers before Durable Object forwarding", () => {
  const req = new Request("https://relay.test/v1/stream/wd_4ksk5edkttwsxqx4?role=client", {
    headers: {
      Authorization: "Bearer secret-ticket",
      "X-WeDecent-Connection-Grant": "secret-grant",
      [INTERNAL_GRANT_JTI_HEADER]: "d90987bf-bae6-45da-ab21-c82d049617bd",
      [INTERNAL_GRANT_EXP_HEADER]: "1",
      Upgrade: "websocket",
    },
  });
  const forwarded = prepareDeviceRelayRequest(
    req,
    { jti, exp },
    "X-WeDecent-Connection-Grant",
  );
  assert.equal(forwarded.headers.get("Authorization"), null);
  assert.equal(forwarded.headers.get("X-WeDecent-Connection-Grant"), null);
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_JTI_HEADER), jti);
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_EXP_HEADER), String(exp));
  assert.equal(forwarded.headers.get("Upgrade"), "websocket");
});

test("consumes a grant jti exactly once", async () => {
  const storage = new MemoryStorage();
  assert.equal((await consumeConnectionGrant(storage, jti, exp, nowMS)).accepted, true);
  assert.equal((await consumeConnectionGrant(storage, jti, exp, nowMS + 1)).accepted, false);
});

test("simultaneous consumption has exactly one winner", async () => {
  const storage = new MemoryStorage();
  const results = await Promise.all(
    Array.from({ length: 8 }, () => consumeConnectionGrant(storage, jti, exp, nowMS)),
  );
  assert.equal(results.filter((result) => result.accepted).length, 1);
});

test("different grant identifiers are independently accepted", async () => {
  const storage = new MemoryStorage();
  const another = "d90987bf-bae6-45da-ab21-c82d049617bd";
  assert.equal((await consumeConnectionGrant(storage, jti, exp, nowMS)).accepted, true);
  assert.equal((await consumeConnectionGrant(storage, another, exp, nowMS)).accepted, true);
});

test("expired replay metadata cannot be consumed", async () => {
  const storage = new MemoryStorage();
  const result = await consumeConnectionGrant(storage, jti, 1_799_999_900, nowMS);
  assert.equal(result.accepted, false);
});

test("cleanup removes expired replay records and keeps the next alarm", async () => {
  const storage = new MemoryStorage();
  const first = await consumeConnectionGrant(storage, jti, exp, nowMS);
  const another = "d90987bf-bae6-45da-ab21-c82d049617bd";
  const second = await consumeConnectionGrant(storage, another, exp + 60, nowMS);
  await scheduleReplayCleanup(storage, second.expiresAtMS);
  await scheduleReplayCleanup(storage, first.expiresAtMS);
  assert.equal(storage.alarm, first.expiresAtMS);

  await cleanupExpiredConnectionGrants(storage, first.expiresAtMS + 1);
  assert.equal(storage.data.size, 1);
  assert.equal(storage.alarm, second.expiresAtMS);
});
