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
