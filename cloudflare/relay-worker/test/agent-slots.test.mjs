import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_AGENT_CONNECTIONS,
  planAgentSlotAdmission,
} from "../src/agent-slots.js";

const open = (slot, peerId = null) => ({
  readyState: 1,
  attachment: { role: "agent", slot, peerId },
});

test("replaces only an unpaired connection for the same slot", () => {
  const previous = open(4);
  const result = planAgentSlotAdmission([open(1, "client-a"), previous], 4);
  assert.equal(result.ok, true);
  assert.deepEqual(result.retire, [previous]);
});

test("rejects a second connection for an occupied active slot", () => {
  const result = planAgentSlotAdmission([open(4, "client-a")], 4);
  assert.equal(result.ok, false);
  assert.equal(result.status, 409);
  assert.deepEqual(result.retire, []);
});

test("caps active agent connections at the configured maximum", () => {
  const agents = Array.from({ length: MAX_AGENT_CONNECTIONS }, (_, index) => open(index + 1, "client-" + index));
  const result = planAgentSlotAdmission(agents, 1);
  assert.equal(result.ok, false);
  assert.equal(result.status, 409);
  assert.deepEqual(result.retire, []);
});

test("rejects a new slot when all connection capacity is occupied", () => {
  const agents = Array.from({ length: MAX_AGENT_CONNECTIONS }, (_, index) => open(index + 1, "client-" + index));
  const result = planAgentSlotAdmission(agents, 1);
  assert.equal(result.ok, false);
  assert.equal(result.status, 409);
});

test("replaces a stale legacy free socket before applying the connection cap", () => {
  const legacy = open(null);
  const agents = [
    legacy,
    ...Array.from({ length: MAX_AGENT_CONNECTIONS - 1 }, (_, index) => open(index + 1, "client-" + index)),
  ];
  const result = planAgentSlotAdmission(agents, 1);
  assert.equal(result.ok, true);
  assert.deepEqual(result.retire, [legacy]);
});

test("rejects invalid slots", () => {
  for (const slot of [0, 33, -1, 1.5, Number.NaN]) {
    const result = planAgentSlotAdmission([], slot);
    assert.equal(result.ok, false);
    assert.equal(result.status, 400);
  }
});
