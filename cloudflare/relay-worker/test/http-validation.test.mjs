import assert from "node:assert/strict";
import test from "node:test";

import {
  directAuthorizationPreflight,
  readBoundedRequestBody,
} from "../src/http-validation.js";

const deviceID = "wd_4ksk5edkttwsxqx4";
const encoder = new TextEncoder();

function streamRequest(chunks, headers = {}) {
  const body = new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
  return { headers: new Headers(headers), body };
}

test("direct authorization rejects unsupported methods before admission", () => {
  const result = directAuthorizationPreflight(
    { method: "GET" },
    new URL("https://relay.test/v1/direct-authorize/" + deviceID),
  );
  assert.equal(result.ok, false);
  assert.equal(result.response.status, 405);
  assert.equal(result.response.headers.get("Allow"), "POST");
});

test("direct authorization rejects malformed and encoded paths before admission", () => {
  for (const path of [
    "/v1/direct-authorize/not-a-device",
    "/v1/direct-authorize/" + deviceID + "/extra",
    "/v1/direct-authorize/%77d_4ksk5edkttwsxqx4",
  ]) {
    const result = directAuthorizationPreflight(
      { method: "POST" },
      new URL("https://relay.test" + path),
    );
    assert.equal(result.ok, false, path);
    assert.equal(result.response.status, 400, path);
  }

  const valid = directAuthorizationPreflight(
    { method: "POST" },
    new URL("https://relay.test/v1/direct-authorize/" + deviceID),
  );
  assert.deepEqual(valid, { ok: true, targetDeviceID: deviceID });
});

test("reads a valid bounded body without relying on Content-Length", async () => {
  const body = encoder.encode(JSON.stringify({ client_device_id: deviceID }));
  const result = await readBoundedRequestBody(streamRequest([body]), 1024);
  assert.equal(result.ok, true);
  assert.equal(result.text, JSON.stringify({ client_device_id: deviceID }));
  assert.equal(result.bytes, body.byteLength);
});

test("rejects an oversized streamed body when Content-Length is absent", async () => {
  const body = encoder.encode("x".repeat(1025));
  const result = await readBoundedRequestBody(streamRequest([body]), 1024);
  assert.deepEqual(result, { ok: false, status: 413 });
});

test("rejects a body whose bytes exceed a misleading smaller Content-Length", async () => {
  const body = encoder.encode("x".repeat(1025));
  const result = await readBoundedRequestBody(streamRequest([body], { "Content-Length": "1" }), 1024);
  assert.deepEqual(result, { ok: false, status: 413 });
});

test("rejects a declared oversized body before reading its stream", async () => {
  let reads = 0;
  const request = {
    headers: new Headers({ "Content-Length": "2048" }),
    body: new ReadableStream({
      pull() { reads++; },
    }),
  };
  const result = await readBoundedRequestBody(request, 1024);
  assert.deepEqual(result, { ok: false, status: 413 });
  assert.equal(reads, 0);
});

test("rejects malformed or mismatched Content-Length values", async () => {
  const body = encoder.encode("hello");
  assert.deepEqual(
    await readBoundedRequestBody(streamRequest([body], { "Content-Length": "5x" }), 1024),
    { ok: false, status: 400 },
  );
  assert.deepEqual(
    await readBoundedRequestBody(streamRequest([body], { "Content-Length": "4" }), 1024),
    { ok: false, status: 400 },
  );
});

test("bounds chunk count as well as byte count", async () => {
  const chunks = Array.from({ length: 65 }, () => Uint8Array.of(0x61));
  const result = await readBoundedRequestBody(streamRequest(chunks), 1024);
  assert.deepEqual(result, { ok: false, status: 413 });
});

test("rejects empty bodies and invalid UTF-8", async () => {
  assert.deepEqual(await readBoundedRequestBody(streamRequest([]), 1024), { ok: false, status: 400 });
  assert.deepEqual(
    await readBoundedRequestBody(streamRequest([Uint8Array.of(0xff)]), 1024),
    { ok: false, status: 400 },
  );
});
