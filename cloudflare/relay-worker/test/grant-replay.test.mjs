import assert from "node:assert/strict";
import test from "node:test";

import {
  agentAdmissionReplayMetadataFromRequest,
  cleanupExpiredConnectionGrants,
  consumeAgentAdmission,
  consumeConnectionGrant,
  INTERNAL_AGENT_ADMISSION_EXP_HEADER,
  INTERNAL_AGENT_ADMISSION_JTI_HEADER,
  INTERNAL_AGENT_LEGACY_HEADER,
  INTERNAL_CLIENT_DEVICE_ID_HEADER,
  INTERNAL_GRANT_EXP_HEADER,
  INTERNAL_GRANT_JTI_HEADER,
  INTERNAL_RELAY_TICKET_EXP_HEADER,
  INTERNAL_RELAY_TICKET_JTI_HEADER,
  prepareAgentRelayRequest,
  prepareDeviceRelayRequest,
  relayTicketReplayMetadataFromRequest,
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
      [INTERNAL_CLIENT_DEVICE_ID_HEADER]: "wd_aaaaaaaaaaaaaaaa",
      Upgrade: "websocket",
    },
  });
  const forwarded = prepareDeviceRelayRequest(
    req,
    { jti, exp },
    "X-WeDecent-Connection-Grant",
    "wd_mw3am46w5weex4a4",
  );
  assert.equal(forwarded.headers.get("Authorization"), null);
  assert.equal(forwarded.headers.get("X-WeDecent-Connection-Grant"), null);
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_JTI_HEADER), jti);
  assert.equal(forwarded.headers.get(INTERNAL_GRANT_EXP_HEADER), String(exp));
  assert.equal(forwarded.headers.get(INTERNAL_CLIENT_DEVICE_ID_HEADER), "wd_mw3am46w5weex4a4");
  assert.equal(forwarded.headers.get("Upgrade"), "websocket");
});

test("agent forwarding strips bearer credentials and injects only trusted replay metadata", () => {
  const ticketJti = Buffer.alloc(16, 1).toString("base64url");
  const req = new Request("https://relay.test/v1/stream/wd_4ksk5edkttwsxqx4?role=agent&slot=4", {
    headers: {
      Authorization: "Bearer self-signed-ticket",
      "X-WeDecent-Agent-Admission": "signed-admission",
      "X-WeDecent-Connection-Grant": "unrelated-grant",
      [INTERNAL_AGENT_ADMISSION_JTI_HEADER]: "attacker-jti",
      [INTERNAL_AGENT_ADMISSION_EXP_HEADER]: "1",
      [INTERNAL_RELAY_TICKET_JTI_HEADER]: "attacker-ticket",
      [INTERNAL_RELAY_TICKET_EXP_HEADER]: "1",
      Upgrade: "websocket",
    },
  });
  const forwarded = prepareAgentRelayRequest(
    req,
    { jti, exp },
    { jti: ticketJti, exp },
    "X-WeDecent-Agent-Admission",
    "X-WeDecent-Connection-Grant",
  );
  assert.equal(forwarded.headers.get("Authorization"), null);
  assert.equal(forwarded.headers.get("X-WeDecent-Agent-Admission"), null);
  assert.equal(forwarded.headers.get("X-WeDecent-Connection-Grant"), null);
  assert.equal(forwarded.headers.get(INTERNAL_AGENT_ADMISSION_JTI_HEADER), jti);
  assert.equal(forwarded.headers.get(INTERNAL_AGENT_ADMISSION_EXP_HEADER), String(exp));
  assert.equal(forwarded.headers.get(INTERNAL_RELAY_TICKET_JTI_HEADER), ticketJti);
  assert.equal(forwarded.headers.get(INTERNAL_RELAY_TICKET_EXP_HEADER), String(exp));
  assert.equal(forwarded.headers.get(INTERNAL_AGENT_LEGACY_HEADER), "0");
  assert.equal(forwarded.headers.get("Upgrade"), "websocket");
});

test("legacy agent forwarding still requires a single-use control-plane admission", () => {
  const req = new Request("https://relay.test/v1/stream/wd_4ksk5edkttwsxqx4?role=agent&slot=4", {
    headers: { Authorization: "Bearer legacy", "X-WeDecent-Agent-Admission": "signed-admission" },
  });
  const forwarded = prepareAgentRelayRequest(
    req,
    { jti, exp },
    null,
    "X-WeDecent-Agent-Admission",
    "X-WeDecent-Connection-Grant",
    true,
  );
  assert.equal(forwarded.headers.get(INTERNAL_AGENT_LEGACY_HEADER), "1");
  assert.equal(forwarded.headers.get(INTERNAL_RELAY_TICKET_JTI_HEADER), null);
  assert.equal(forwarded.headers.get("Authorization"), null);
});

test("parses only well-formed agent admission and relay-ticket replay metadata", () => {
  const ticketJti = Buffer.alloc(16, 1).toString("base64url");
  const req = new Request("https://relay.test", {
    headers: {
      [INTERNAL_AGENT_ADMISSION_JTI_HEADER]: jti,
      [INTERNAL_AGENT_ADMISSION_EXP_HEADER]: String(exp),
      [INTERNAL_RELAY_TICKET_JTI_HEADER]: ticketJti,
      [INTERNAL_RELAY_TICKET_EXP_HEADER]: String(exp),
    },
  });
  assert.deepEqual(agentAdmissionReplayMetadataFromRequest(req), { jti, exp });
  assert.deepEqual(relayTicketReplayMetadataFromRequest(req), { jti: ticketJti, exp });

  const bad = new Request("https://relay.test", {
    headers: {
      [INTERNAL_AGENT_ADMISSION_JTI_HEADER]: "not-a-jti",
      [INTERNAL_AGENT_ADMISSION_EXP_HEADER]: String(exp),
      [INTERNAL_RELAY_TICKET_JTI_HEADER]: "short",
      [INTERNAL_RELAY_TICKET_EXP_HEADER]: String(exp),
    },
  });
  assert.equal(agentAdmissionReplayMetadataFromRequest(bad), null);
  assert.equal(relayTicketReplayMetadataFromRequest(bad), null);
});

test("consumes agent admission and relay-ticket identifiers atomically exactly once", async () => {
  const storage = new MemoryStorage();
  const ticketJti = Buffer.alloc(16, 2).toString("base64url");
  const first = await consumeAgentAdmission(storage, jti, exp, ticketJti, exp, nowMS);
  assert.equal(first.accepted, true);
  assert.equal((await consumeAgentAdmission(storage, jti, exp, ticketJti, exp, nowMS + 1)).accepted, false);

  const anotherAdmission = "d90987bf-bae6-45da-ab21-c82d049617bd";
  assert.equal((await consumeAgentAdmission(storage, anotherAdmission, exp, ticketJti, exp, nowMS)).accepted, false);
});

test("simultaneous agent admission replay consumption has exactly one winner", async () => {
  const storage = new MemoryStorage();
  const results = await Promise.all(
    Array.from({ length: 8 }, () => consumeAgentAdmission(storage, jti, exp, null, null, nowMS)),
  );
  assert.equal(results.filter((result) => result.accepted).length, 1);
});

test("expired agent admission capabilities cannot be consumed", async () => {
  const storage = new MemoryStorage();
  const result = await consumeAgentAdmission(storage, jti, 1_799_999_900, null, null, nowMS);
  assert.equal(result.accepted, false);
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

test("replay cleanup expires agent admission and relay ticket keys without changing legacy grant keys", async () => {
  const storage = new MemoryStorage();
  const ticketJti = Buffer.alloc(16, 3).toString("base64url");
  const consumed = await consumeAgentAdmission(storage, jti, exp, ticketJti, exp, nowMS);
  assert.equal(consumed.accepted, true);
  await scheduleReplayCleanup(storage, consumed.expiresAtMS);
  await cleanupExpiredConnectionGrants(storage, consumed.expiresAtMS + 1);
  assert.equal(storage.data.size, 0);
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
