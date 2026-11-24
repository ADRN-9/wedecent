import {
  canonical,
  checkpointHeadMessage,
  checkpointReceiptMessage,
  checkpointRecordHash,
  concat,
  digest,
  h32,
  i64,
  providerKeyID,
  sha,
  str,
  u32,
  u64,
  verifyFinalizationEvidence,
  verifyRouteAuthorization,
  witnessAckMessage,
  witnessHeadMessage,
} from "./index.ts";

Deno.test("shared Go and TypeScript checkpoint cryptographic golden vectors", async () => {
  const vector = JSON.parse(await Deno.readTextFile(new URL("../../../testdata/portforward/checkpoint_crypto_vectors.json", import.meta.url)));
  const hex = (value: Uint8Array) => [...value].map((x) => x.toString(16).padStart(2, "0")).join("");
  const requestMessage = Uint8Array.from(vector.request.message_hex.match(/../g), (x: string) => parseInt(x, 16));
  if (hex(await sha(requestMessage)) !== vector.request.fingerprint_sha256) throw new Error("request fingerprint vector mismatch");
  const operationID = hex(await sha(concat(new TextEncoder().encode("wedecent-checkpoint-finalization-v1\n"), h32(vector.request.fingerprint_sha256))));
  if (operationID !== vector.request.operation_id) throw new Error("operation ID newline or digest vector mismatch");
  if (hex(checkpointReceiptMessage(vector.primary_receipt)) !== vector.primary_receipt.message_hex) throw new Error("primary receipt vector mismatch");
  if (hex(checkpointHeadMessage(vector.primary_head)) !== vector.primary_head.message_hex) throw new Error("primary head vector mismatch");
  if (hex(witnessAckMessage(vector.witness_ack)) !== vector.witness_ack.message_hex) throw new Error("witness acknowledgement vector mismatch");
  if (hex(witnessHeadMessage(vector.witness_head)) !== vector.witness_head.message_hex) throw new Error("witness head vector mismatch");
  if (await digest(vector.canonical_payload.value) !== vector.canonical_payload.sha256) throw new Error("canonical payload digest vector mismatch");
});

const evidence = {
  primary_receipt: { public_key: btoa("x".repeat(32)) },
  witness_acknowledgements: [],
  revocation_proofs: [],
};

async function rejectsWith(message: string, configure: () => void) {
  const previousPrimary = Deno.env.get("WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY");
  const previousWitnesses = Deno.env.get("WEDECENT_CHECKPOINT_WITNESS_KEYS");
  const previousQuorum = Deno.env.get("WEDECENT_CHECKPOINT_WITNESS_QUORUM");
  Deno.env.delete("WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY");
  Deno.env.delete("WEDECENT_CHECKPOINT_WITNESS_KEYS");
  Deno.env.delete("WEDECENT_CHECKPOINT_WITNESS_QUORUM");
  configure();
  try {
    const sum = await digest(evidence);
    await verifyFinalizationEvidence({}, "0".repeat(64), new Uint8Array(32), evidence, sum);
    throw new Error("expected trust configuration rejection");
  } catch (error) {
    if (!(error instanceof Error) || !error.message.includes(message)) throw error;
  } finally {
    if (previousPrimary === undefined) Deno.env.delete("WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY");
    else Deno.env.set("WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY", previousPrimary);
    if (previousWitnesses === undefined) Deno.env.delete("WEDECENT_CHECKPOINT_WITNESS_KEYS");
    else Deno.env.set("WEDECENT_CHECKPOINT_WITNESS_KEYS", previousWitnesses);
    if (previousQuorum === undefined) Deno.env.delete("WEDECENT_CHECKPOINT_WITNESS_QUORUM");
    else Deno.env.set("WEDECENT_CHECKPOINT_WITNESS_QUORUM", previousQuorum);
  }
}

Deno.test("terminal audit ignores caller-supplied primary public key", async () => {
  await rejectsWith("independent primary trust anchor missing", () => {});
});

Deno.test("terminal audit requires independently provisioned witness keys", async () => {
  await rejectsWith("independent witness trust anchors missing", () => {
    Deno.env.set("WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY", btoa("p".repeat(32)));
  });
});




function hex(bytes: Uint8Array) {
  return [...bytes].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function standardBase64(bytes: Uint8Array) {
  let raw = "";
  for (const value of bytes) raw += String.fromCharCode(value);
  return btoa(raw);
}
async function signingKey() {
  return await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
}
function bufferSource(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer as ArrayBuffer;
}
async function sign(key: CryptoKey, message: Uint8Array) {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, bufferSource(message)));
}
async function positiveEvidenceFixture() {
  const primary = await signingKey();
  const witnessA = await signingKey();
  const witnessB = await signingKey();
  const primaryRaw = new Uint8Array(await crypto.subtle.exportKey("raw", primary.publicKey));
  const witnessARaw = new Uint8Array(await crypto.subtle.exportKey("raw", witnessA.publicKey));
  const witnessBRaw = new Uint8Array(await crypto.subtle.exportKey("raw", witnessB.publicKey));
  const primaryID = await providerKeyID(primaryRaw);
  const witnessAID = await providerKeyID(witnessARaw);
  const witnessBID = await providerKeyID(witnessBRaw);
  const initiator = {
    device_id: "wd_aaaaaaaaaaaaaaaa",
    account_id: "11111111-1111-4111-8111-111111111111",
    organization_id: "33333333-3333-4333-8333-333333333333",
    revocation_epoch: 0,
  };
  const destination = {
    device_id: "wd_bbbbbbbbbbbbbbbb",
    account_id: "22222222-2222-4222-8222-222222222222",
    organization_id: "33333333-3333-4333-8333-333333333333",
    revocation_epoch: 0,
  };
  const payload = {
    initiator,
    destination,
    router: null,
    consuming_device_id: initiator.device_id,
    jti: "AAAAAAAAAAAAAAAAAAAAAA",
    authorization_sha256: "a".repeat(64),
  };
  const requestHash = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
  const previous = new Uint8Array(32);
  const recordHash = await checkpointRecordHash(previous, 1, requestHash);
  const receipt: Record<string, unknown> = {
    version: 1,
    device_id: initiator.device_id,
    account_id: initiator.account_id,
    organization_id: initiator.organization_id,
    jti: payload.jti,
    authorization_sha256: payload.authorization_sha256,
    request_sha256: hex(requestHash),
    generation: 1,
    previous_hash: hex(previous),
    record_hash: hex(recordHash),
    provider_key_id: primaryID,
    signature: "",
  };
  receipt.signature = standardBase64(await sign(primary.privateKey, checkpointReceiptMessage(receipt)));
  const receiptDigest = hex(await sha(checkpointReceiptMessage(receipt)));
  const ack = async (id: string, keyID: string, key: CryptoKey): Promise<Record<string, unknown>> => {
    const value: Record<string, unknown> = {
      witness_id: id,
      scope: { device_id: initiator.device_id, account_id: initiator.account_id, organization_id: initiator.organization_id },
      jti: payload.jti,
      request_sha256: hex(requestHash),
      primary_receipt_sha256: receiptDigest,
      decision: "committed",
      status: "acknowledged",
      witness_key_id: keyID,
      signature: "",
    };
    value.signature = standardBase64(await sign(key, witnessAckMessage(value)));
    return value;
  };
  const primaryHead = async (scope: typeof initiator, generation: number, record: Uint8Array) => {
    const value: Record<string, unknown> = {
      version: 1, device_id: scope.device_id, account_id: scope.account_id,
      organization_id: scope.organization_id, generation, record_hash: hex(record),
      revocation_epoch: scope.revocation_epoch, provider_key_id: primaryID, signature: "",
    };
    value.signature = standardBase64(await sign(primary.privateKey, checkpointHeadMessage(value)));
    return value;
  };
  const witnessHead = async (id: string, keyID: string, key: CryptoKeyPair, scope: typeof initiator, generation: number, primaryGeneration: number, primaryRecord: Uint8Array) => {
    const value: Record<string, unknown> = {
      witness_id: id,
      scope: { device_id: scope.device_id, account_id: scope.account_id, organization_id: scope.organization_id },
      generation, record_hash: hex(new Uint8Array(32)),
      primary_generation: primaryGeneration, primary_head: hex(primaryRecord),
      revocation_epoch: scope.revocation_epoch, witness_key_id: keyID, signature: "",
    };
    value.signature = standardBase64(await sign(key.privateKey, witnessHeadMessage(value)));
    return value;
  };
  const initiatorHead = await primaryHead(initiator, 1, recordHash);
  const destinationHead = await primaryHead(destination, 0, new Uint8Array(32));
  const evidence = {
    primary_receipt: receipt,
    witness_acknowledgements: [await ack("witness-a", witnessAID, witnessA.privateKey), await ack("witness-b", witnessBID, witnessB.privateKey)],
    revocation_proofs: [
      { primary_head: initiatorHead, witness_heads: [await witnessHead("witness-a", witnessAID, witnessA, initiator, 1, 1, recordHash), await witnessHead("witness-b", witnessBID, witnessB, initiator, 1, 1, recordHash)] },
      { primary_head: destinationHead, witness_heads: [await witnessHead("witness-a", witnessAID, witnessA, destination, 0, 0, new Uint8Array(32)), await witnessHead("witness-b", witnessBID, witnessB, destination, 0, 0, new Uint8Array(32))] },
    ],
  };
  const operationID = hex(await sha(concat(new TextEncoder().encode("wedecent-checkpoint-finalization-v1\n"), requestHash)));
  return {
    primaryRaw, witnessARaw, witnessBRaw,
    payload, requestHash, evidence, operationID,
  };
}

Deno.test("terminal audit accepts an independently signed primary receipt and witness quorum", async () => {
  const fixture = await positiveEvidenceFixture();
  const old = {
    primary: Deno.env.get("WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY"),
    witnesses: Deno.env.get("WEDECENT_CHECKPOINT_WITNESS_KEYS"),
    quorum: Deno.env.get("WEDECENT_CHECKPOINT_WITNESS_QUORUM"),
  };
  try {
    Deno.env.set("WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY", standardBase64(fixture.primaryRaw));
    Deno.env.set("WEDECENT_CHECKPOINT_WITNESS_KEYS", JSON.stringify({
      "witness-a": standardBase64(fixture.witnessARaw),
      "witness-b": standardBase64(fixture.witnessBRaw),
    }));
    Deno.env.set("WEDECENT_CHECKPOINT_WITNESS_QUORUM", "2");
    await verifyFinalizationEvidence(
      fixture.payload, fixture.operationID, fixture.requestHash,
      fixture.evidence, await digest(fixture.evidence),
    );
  } finally {
    for (const [key, value] of [
      ["WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY", old.primary],
      ["WEDECENT_CHECKPOINT_WITNESS_KEYS", old.witnesses],
      ["WEDECENT_CHECKPOINT_WITNESS_QUORUM", old.quorum],
    ] as const) {
      if (value === undefined) Deno.env.delete(key);
      else Deno.env.set(key, value);
    }
  }
});

Deno.test("terminal audit rejects an altered witness acknowledgement", async () => {
  const fixture = await positiveEvidenceFixture();
  const old = {
    primary: Deno.env.get("WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY"),
    witnesses: Deno.env.get("WEDECENT_CHECKPOINT_WITNESS_KEYS"),
    quorum: Deno.env.get("WEDECENT_CHECKPOINT_WITNESS_QUORUM"),
  };
  try {
    Deno.env.set("WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY", standardBase64(fixture.primaryRaw));
    Deno.env.set("WEDECENT_CHECKPOINT_WITNESS_KEYS", JSON.stringify({
      "witness-a": standardBase64(fixture.witnessARaw),
      "witness-b": standardBase64(fixture.witnessBRaw),
    }));
    Deno.env.set("WEDECENT_CHECKPOINT_WITNESS_QUORUM", "2");
    const changed = structuredClone(fixture.evidence) as typeof fixture.evidence;
    const signature = String(changed.witness_acknowledgements[0].signature);
    changed.witness_acknowledgements[0].signature = signature.slice(0, -4) + "AAAA";
    try {
      await verifyFinalizationEvidence(fixture.payload, fixture.operationID, fixture.requestHash, changed, await digest(changed));
      throw new Error("tampered witness acknowledgement accepted");
    } catch (error) {
      if (!(error instanceof Error) || error.message === "tampered witness acknowledgement accepted") throw error;
    }
  } finally {
    for (const [key, value] of [
      ["WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY", old.primary],
      ["WEDECENT_CHECKPOINT_WITNESS_KEYS", old.witnesses],
      ["WEDECENT_CHECKPOINT_WITNESS_QUORUM", old.quorum],
    ] as const) {
      if (value === undefined) Deno.env.delete(key);
      else Deno.env.set(key, value);
    }
  }
});


function urlBase64(bytes: Uint8Array) {
  let raw = "";
  for (const value of bytes) raw += String.fromCharCode(value);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

Deno.test("routed terminal audit verifies the independent route authorization signature", async () => {
  const routeKey = await signingKey();
  const primary = await signingKey();
  const witnessA = await signingKey();
  const witnessB = await signingKey();
  const raw = async (key: CryptoKey) => new Uint8Array(await crypto.subtle.exportKey("raw", key));
  const old = {
    routeID: Deno.env.get("WEDECENT_ROUTE_AUTH_KEY_ID"),
    routeKey: Deno.env.get("WEDECENT_ROUTE_AUTH_PUBLIC_KEY"),
    primary: Deno.env.get("WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY"),
    witnesses: Deno.env.get("WEDECENT_CHECKPOINT_WITNESS_KEYS"),
    quorum: Deno.env.get("WEDECENT_CHECKPOINT_WITNESS_QUORUM"),
  };
  try {
    const primaryRaw = await raw(primary.publicKey);
    const witnessARaw = await raw(witnessA.publicKey);
    const witnessBRaw = await raw(witnessB.publicKey);
    const routeRaw = await raw(routeKey.publicKey);
    Deno.env.set("WEDECENT_ROUTE_AUTH_KEY_ID", "route-key-v1");
    Deno.env.set("WEDECENT_ROUTE_AUTH_PUBLIC_KEY", standardBase64(routeRaw));
    Deno.env.set("WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY", standardBase64(primaryRaw));
    Deno.env.set("WEDECENT_CHECKPOINT_WITNESS_KEYS", JSON.stringify({
      "witness-a": standardBase64(witnessARaw),
      "witness-b": standardBase64(witnessBRaw),
    }));
    Deno.env.set("WEDECENT_CHECKPOINT_WITNESS_QUORUM", "2");
    const initiator = "wd_aaaaaaaaaaaaaaaa";
    const destination = "wd_bbbbbbbbbbbbbbbb";
    const router = "wd_cccccccccccccccc";
    const issued = Date.now() - 1000;
    const expires = issued + 60000;
    const jti = "AAAAAAAAAAAAAAAAAAAAAA";
    const routeID = "55000000-0000-4000-8000-000000000091";
    const claims = {
      v: 1,
      iss: "wedecent-control-plane",
      aud: "wedecent-mesh-router",
      permission: "mesh.forward",
      jti,
      router,
      route: {
        ID: routeID,
        Source: initiator,
        Destination: destination,
        Hops: [
          { From: initiator, To: router, Transport: "lan", Cost: 1 },
          { From: router, To: destination, Transport: "lan", Cost: 1 },
        ],
        ExpiresAt: new Date(expires).toISOString(),
      },
      iat_unix_ms: issued,
      exp_unix_ms: expires,
    };
    const auth: Record<string, unknown> = { kid: "route-key-v1", claims, signature: "" };
    const fields = [
      "route-key-v1", claims.iss, claims.aud, claims.permission, claims.jti,
      claims.router, claims.route.ID, claims.route.Source, claims.route.Destination,
    ];
    const message = concat(
      str("wedecent-mesh-forward-v1"),
      u32(1),
      ...fields.map((value) => str(value)),
      i64(issued), i64(expires), i64(expires), u32(2),
      str(initiator), str(router), str("lan"), u64(1),
      str(router), str(destination), str("lan"), u64(1),
    );
    auth.signature = urlBase64(await sign(routeKey.privateKey, message));
    const payload = {
      initiator: { device_id: initiator },
      destination: { device_id: destination },
      router: { device_id: router },
      route_authorization_id: routeID,
      route_authorization_jti: jti,
    };
    await verifyRouteAuthorization(auth, payload);
    try {
      await verifyRouteAuthorization(auth, { ...payload, destination: { device_id: initiator } });
      throw new Error("mismatched route participant accepted");
    } catch (error) {
      if (!(error instanceof Error) || error.message === "mismatched route participant accepted") throw error;
    }
  } finally {
    for (const [key, value] of [
      ["WEDECENT_ROUTE_AUTH_KEY_ID", old.routeID],
      ["WEDECENT_ROUTE_AUTH_PUBLIC_KEY", old.routeKey],
      ["WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY", old.primary],
      ["WEDECENT_CHECKPOINT_WITNESS_KEYS", old.witnesses],
      ["WEDECENT_CHECKPOINT_WITNESS_QUORUM", old.quorum],
    ] as const) {
      if (value === undefined) Deno.env.delete(key);
      else Deno.env.set(key, value);
    }
  }
});


Deno.test("TypeScript canonical JSON matches shared Go and SQL vectors", async () => {
  const fixtureURL = new URL("../../tests/fixtures/checkpoint-audit-canonical-vectors.json", import.meta.url);
  const fixture = JSON.parse(await Deno.readTextFile(fixtureURL));
  for (const vector of fixture.vectors) {
    if (canonical(vector.input) !== vector.canonical) {
      throw new Error("canonical vector mismatch: " + vector.name);
    }
    if (await digest(vector.input) !== vector.sha256) {
      throw new Error("canonical digest mismatch: " + vector.name);
    }
  }
  for (const vector of fixture.invalid) {
    try {
      canonical(vector.input);
      throw new Error("unsafe canonical number accepted: " + vector.name);
    } catch (error) {
      if (!(error instanceof Error) || error.message.startsWith("unsafe canonical number accepted:")) throw error;
    }
  }
});
