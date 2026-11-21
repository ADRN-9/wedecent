import {
  withBoundedDatabaseRetry,
  type DatabaseRPCResult,
} from "./database-rpc-retry.ts";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

Deno.test("retries serialization failures with a bounded backoff", async () => {
  let calls = 0;
  const delays: number[] = [];
  const result = await withBoundedDatabaseRetry<string>(
    async () => {
      calls += 1;
      return calls < 3
        ? { data: null, error: { code: "40001" } }
        : { data: "committed", error: null };
    },
    { sleep: async (milliseconds) => { delays.push(milliseconds); } },
  );

  assert(calls === 3, "serialization retry count must stop at success");
  assert(result.data === "committed" && result.error === null, "successful result must be returned");
  assert(delays.join(",") === "20,40", "retry delay must use bounded exponential backoff");
});

Deno.test("retries deadlocks but not duplicate or authorization failures", async () => {
  let deadlockCalls = 0;
  const deadlockResult = await withBoundedDatabaseRetry<string>(
    async () => {
      deadlockCalls += 1;
      return deadlockCalls === 1
        ? { data: null, error: { code: "40P01" } }
        : { data: "ok", error: null };
    },
    { sleep: async () => {} },
  );
  assert(deadlockCalls === 2 && deadlockResult.data === "ok", "deadlock should retry once");

  let duplicateCalls = 0;
  const duplicate: DatabaseRPCResult<string> = await withBoundedDatabaseRetry<string>(
    async () => {
      duplicateCalls += 1;
      return { data: null, error: { code: "23505" } };
    },
    { sleep: async () => { throw new Error("non-transient error must not sleep"); } },
  );
  assert(duplicateCalls === 1 && duplicate.error?.code === "23505", "duplicate must not retry");
});

Deno.test("returns the final transient error after exactly three attempts", async () => {
  let calls = 0;
  const result = await withBoundedDatabaseRetry<string>(
    async () => {
      calls += 1;
      return { data: null, error: { code: "40P01" } };
    },
    { sleep: async () => {} },
  );

  assert(calls === 3, "retry attempts must be capped at three");
  assert(result.error?.code === "40P01", "last deadlock error must be returned");
});

Deno.test("does not retry thrown or ambiguous transport failures", async () => {
  let calls = 0;
  try {
    await withBoundedDatabaseRetry<string>(
      async () => {
        calls += 1;
        throw new Error("connection reset");
      },
      { sleep: async () => {} },
    );
    throw new Error("expected operation to throw");
  } catch (error) {
    assert(error instanceof Error && error.message === "connection reset", "original transport error must propagate");
  }
  assert(calls === 1, "ambiguous transport failure must not retry");
});

Deno.test("rejects retry limits above the hard cap", async () => {
  let rejected = false;
  try {
    await withBoundedDatabaseRetry<string>(
      async () => ({ data: "unused", error: null }),
      { maxAttempts: 4 },
    );
  } catch (error) {
    rejected = error instanceof RangeError;
  }
  assert(rejected, "maxAttempts above three must be rejected");
});
