import { digest, verifyFinalizationEvidence } from "./index.ts";

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


import {
  checkpointHeadMessage,
  checkpointReceiptMessage,
  checkpointRecordHash,
  concat,
  providerKeyID,
  sha,
  verifyFinalizationEvidence,
  witnessAckMessage,
  witnessHeadMessage,
} from "./index.ts";

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
async function sign(key: CryptoKey, message: Uint8Array) {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, message));
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
  const witnessHead = async (id: string, keyID: string, key: CryptoKey, scope: typeof initiator, generation: number, primaryGeneration: number, primaryRecord: Uint8Array) => {
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
  const operationID = hex(await sha(concat(new TextEncoder().encode("wedecent-checkpoint-finalization-v1\\n"), requestHash)));
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
