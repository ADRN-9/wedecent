import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_SESSION_IDLE_TIMEOUT_MS,
  MAX_AGENT_SESSION_LIFETIME_MS,
  agentSessionExpired,
  createAgentSessionAttachment,
  nextAgentSessionExpiry,
  touchAgentSessionAttachment,
} from "../src/agent-session-policy.js";

test("agent sessions expire at the absolute lifetime even with recent activity", () => {
  const createdAtMS = 1_000;
  let attachment = createAgentSessionAttachment({
    id: "agent",
    role: "agent",
    authorizationGeneration: 1,
    peerId: null,
    absoluteExpiresAtMS: createdAtMS + MAX_AGENT_SESSION_LIFETIME_MS,
  }, createdAtMS);
  attachment = {
    ...attachment,
    lastActivityAtMS: createdAtMS + MAX_AGENT_SESSION_LIFETIME_MS - 2_000,
  };
  attachment = touchAgentSessionAttachment(attachment, createdAtMS + MAX_AGENT_SESSION_LIFETIME_MS - 1);
  assert.notEqual(attachment, null);
  assert.equal(agentSessionExpired(attachment, createdAtMS + MAX_AGENT_SESSION_LIFETIME_MS), true);
});

test("agent sessions expire after the idle timeout and activity refreshes only idle expiry", () => {
  const createdAtMS = 2_000;
  const attachment = createAgentSessionAttachment({ id: "agent", role: "agent",
    authorizationGeneration: 1, peerId: null }, createdAtMS);
  assert.equal(agentSessionExpired(attachment, createdAtMS + AGENT_SESSION_IDLE_TIMEOUT_MS), true);
  const touched = touchAgentSessionAttachment(attachment, createdAtMS + 10_000);
  assert.notEqual(touched, null);
  assert.equal(agentSessionExpired(touched, createdAtMS + 10_000 + AGENT_SESSION_IDLE_TIMEOUT_MS - 1), false);
  assert.equal(agentSessionExpired(touched, createdAtMS + MAX_AGENT_SESSION_LIFETIME_MS), true);
});

test("missing, malformed, or future session timestamps fail closed", () => {
  const nowMS = 10_000;
  assert.equal(agentSessionExpired({ role: "agent" }, nowMS), true);
  assert.equal(agentSessionExpired({ role: "agent", createdAtMS: 1, lastActivityAtMS: 20_000 }, nowMS), true);
  assert.equal(touchAgentSessionAttachment({ role: "agent" }, nowMS), null);
});

test("next expiry selects the earliest live agent deadline and ignores non-agent sockets", () => {
  const nowMS = 5_000;
  const first = createAgentSessionAttachment({ id: "a", role: "agent", authorizationGeneration: 1 }, nowMS);
  const second = createAgentSessionAttachment({ id: "b", role: "agent", authorizationGeneration: 1 }, nowMS + 2_000);
  const next = nextAgentSessionExpiry([
    { readyState: 1, attachment: first },
    { readyState: 1, attachment: { role: "client" } },
    { readyState: 3, attachment: second },
    { readyState: 1, attachment: second },
  ], nowMS + 2_000);
  assert.equal(next, nowMS + AGENT_SESSION_IDLE_TIMEOUT_MS);
});

test("invalid absolute expiry fails closed", () => {
  assert.throws(() => createAgentSessionAttachment({
    id: "agent",
    role: "agent",
    authorizationGeneration: 1,
    absoluteExpiresAtMS: 9_999,
  }, 10_000), /absolute expiry/);
});

test("an expired open socket requests an immediate cleanup alarm", () => {
  const createdAtMS = 100;
  const attachment = createAgentSessionAttachment({ id: "a", role: "agent", authorizationGeneration: 1 }, createdAtMS);
  assert.equal(
    nextAgentSessionExpiry([{ readyState: 1, attachment }], createdAtMS + AGENT_SESSION_IDLE_TIMEOUT_MS),
    createdAtMS + AGENT_SESSION_IDLE_TIMEOUT_MS,
  );
});
