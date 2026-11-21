export type DatabaseRPCError = {
  code?: string;
};

export type DatabaseRPCResult<T> = {
  data: T | null;
  error: DatabaseRPCError | null;
};

export type RetryOptions = {
  maxAttempts?: number;
  baseDelayMs?: number;
  sleep?: (milliseconds: number) => Promise<void>;
};

const RETRYABLE_SQLSTATES = new Set(["40001", "40P01"]);
const MAX_ATTEMPTS = 3;

function defaultSleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

// Retry only explicit PostgreSQL transaction-abort codes. Network errors and
// application errors are not retried because the commit outcome may be unknown.
export async function withBoundedDatabaseRetry<T>(
  operation: () => PromiseLike<DatabaseRPCResult<T>>,
  options: RetryOptions = {},
): Promise<DatabaseRPCResult<T>> {
  const maxAttempts = options.maxAttempts ?? MAX_ATTEMPTS;
  const baseDelayMs = options.baseDelayMs ?? 20;
  const sleep = options.sleep ?? defaultSleep;

  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > MAX_ATTEMPTS) {
    throw new RangeError("maxAttempts must be between 1 and 3");
  }
  if (!Number.isInteger(baseDelayMs) || baseDelayMs < 0 || baseDelayMs > 1000) {
    throw new RangeError("baseDelayMs must be between 0 and 1000");
  }

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const result = await operation();
    const code = result.error?.code ?? "";

    if (!result.error || !RETRYABLE_SQLSTATES.has(code) || attempt === maxAttempts) {
      return result;
    }

    await sleep(baseDelayMs * (2 ** (attempt - 1)));
  }

  throw new Error("unreachable database retry state");
}
