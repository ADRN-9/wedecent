const DIRECT_AUTHORIZE_PREFIX = "/v1/direct-authorize/";
const DEVICE_ID = /^wd_[a-z2-7]{16}$/;
const MAX_BODY_CHUNKS = 64;

export function directAuthorizationPreflight(request, url) {
  if (request.method !== "POST") {
    return {
      ok: false,
      response: new Response("Method not allowed", {
        status: 405,
        headers: { Allow: "POST", "Cache-Control": "no-store" },
      }),
    };
  }

  const targetDeviceID = url.pathname.slice(DIRECT_AUTHORIZE_PREFIX.length);
  if (!DEVICE_ID.test(targetDeviceID)) {
    return {
      ok: false,
      response: new Response("Invalid device ID", {
        status: 400,
        headers: { "Cache-Control": "no-store" },
      }),
    };
  }

  return { ok: true, targetDeviceID };
}

export async function readBoundedRequestBody(request, maxBytes) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 65_536) {
    throw new Error("invalid request body limit");
  }

  const declaredText = request.headers.get("Content-Length");
  let declaredLength = null;
  if (declaredText !== null) {
    if (!/^[0-9]+$/.test(declaredText)) {
      return { ok: false, status: 400 };
    }
    declaredLength = Number(declaredText);
    if (!Number.isSafeInteger(declaredLength)) {
      return { ok: false, status: 400 };
    }
    if (declaredLength > maxBytes) {
      return { ok: false, status: 413 };
    }
  }

  if (!request.body || typeof request.body.getReader !== "function") {
    return { ok: false, status: 400 };
  }

  const reader = request.body.getReader();
  const chunks = [];
  let totalBytes = 0;
  let chunkCount = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) {
        await cancelReader(reader);
        return { ok: false, status: 400 };
      }

      chunkCount++;
      totalBytes += value.byteLength;
      if (chunkCount > MAX_BODY_CHUNKS || totalBytes > maxBytes) {
        await cancelReader(reader);
        return { ok: false, status: 413 };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, status: 400 };
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // A failed release cannot make an already-rejected body acceptable.
    }
  }

  if (totalBytes === 0 || (declaredLength !== null && declaredLength !== totalBytes)) {
    return { ok: false, status: 400 };
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return {
      ok: true,
      text: new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      bytes: totalBytes,
    };
  } catch {
    return { ok: false, status: 400 };
  }
}

function cancelReader(reader) {
  try {
    const cancelled = reader.cancel();
    if (cancelled && typeof cancelled.catch === "function") {
      void cancelled.catch(() => {});
    }
  } catch {
    // Cancellation is best effort; the byte and chunk bounds remain enforced.
  }
}
