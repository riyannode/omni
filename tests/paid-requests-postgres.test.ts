import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { SQL } from "bun";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createPaidRequestStore, type PaymentMetadata } from "../src/data/paid-requests.ts";

const databaseUrl = process.env.TEST_DATABASE_URL;
const postgresTest = test.if(Boolean(databaseUrl));
let setupDb: SQL | undefined;

beforeAll(async () => {
  if (!databaseUrl) return;
  setupDb = new SQL(databaseUrl);
  await setupDb.unsafe(await readFile(new URL("../db/schema.sql", import.meta.url), "utf8"));
});

afterAll(async () => {
  await setupDb?.close();
});

const payment: PaymentMetadata = {
  paymentNonce: `0x${"a".repeat(64)}`,
  payer: "0x2222222222222222222222222222222222222222",
  network: "eip155:5042002",
  payTo: "0x1111111111111111111111111111111111111111",
  asset: "0x3333333333333333333333333333333333333333",
  amountAtomic: "5000"
};

describe("Postgres paid request store (requires TEST_DATABASE_URL)", () => {
  postgresTest("enforces reservation, payment claim, lease fencing, no-nonce reset, non-regression, and completion", async () => {
    if (!databaseUrl || !setupDb) throw new Error("TEST_DATABASE_URL missing");
    const store = createPaidRequestStore(databaseUrl);
    const key = randomUUID();
    const noNonceKey = randomUUID();
    const fingerprint = "f".repeat(64);
    const noNonceFingerprint = "e".repeat(64);
    try {
      const reservations = await Promise.all([
        store.reserve(key, fingerprint, "package"),
        store.reserve(key, fingerprint, "package")
      ]);
      expect(reservations.filter(result => result.kind === "created")).toHaveLength(1);
      expect(reservations.filter(result => result.kind === "existing")).toHaveLength(1);

      const claims = await Promise.all([
        store.claimPaymentAttempt(key, fingerprint),
        store.claimPaymentAttempt(key, fingerprint)
      ]);
      expect(claims.filter(Boolean)).toHaveLength(1);

      await store.persistPaymentNonce(key, fingerprint, payment);
      await store.markPaid(key, fingerprint, "circle-transfer", payment);
      await store.markRecoveryPending(key, fingerprint);
      expect(await store.get(key)).toMatchObject({ state: "paid" });
      const firstClaim = await store.claimExecution(key, fingerprint, 30_000);
      expect(firstClaim).toMatchObject({ kind: "claimed" });
      if (typeof firstClaim !== "object") throw new Error("first execution lease missing");
      expect(await store.renewExecution(key, fingerprint, firstClaim.leaseId)).toBe(true);
      expect(await store.renewExecution(key, fingerprint, randomUUID())).toBe(false);
      expect(await store.claimExecution(key, fingerprint, 30_000)).toBe("busy");

      await setupDb`UPDATE paid_requests SET execution_lease_at = now() - interval '1 minute' WHERE idempotency_key = ${key}`;
      const staleReclaim = await store.claimExecution(key, fingerprint, 30_000);
      expect(staleReclaim).toMatchObject({ kind: "claimed" });
      if (typeof staleReclaim !== "object") throw new Error("stale reclaim lease missing");
      expect(staleReclaim.leaseId).not.toBe(firstClaim.leaseId);
      expect(await store.renewExecution(key, fingerprint, firstClaim.leaseId)).toBe(false);
      expect(await store.renewExecution(key, fingerprint, staleReclaim.leaseId)).toBe(true);
      expect(await store.claimExecution(key, fingerprint, 30_000)).toBe("busy");

      await expect(store.complete(key, fingerprint, firstClaim.leaseId, { stale: true }, 200)).rejects.toThrow();
      await store.releaseExecution(key, fingerprint, firstClaim.leaseId);
      expect(await store.get(key)).toMatchObject({ state: "running" });

      await store.markRecoveryPending(key, fingerprint);
      expect(await store.get(key)).toMatchObject({ state: "running" });
      await setupDb`UPDATE paid_requests SET execution_lease_at = now() - interval '1 minute' WHERE idempotency_key = ${key}`;
      const finalReclaim = await store.claimExecution(key, fingerprint, 30_000);
      expect(finalReclaim).toMatchObject({ kind: "claimed" });
      if (typeof finalReclaim !== "object") throw new Error("final reclaim lease missing");
      expect(await store.renewExecution(key, fingerprint, staleReclaim.leaseId)).toBe(false);
      await expect(store.complete(key, fingerprint, staleReclaim.leaseId, { stale: true }, 200)).rejects.toThrow();
      await store.releaseExecution(key, fingerprint, staleReclaim.leaseId);
      expect(await store.get(key)).toMatchObject({ state: "running" });
      await store.complete(key, fingerprint, finalReclaim.leaseId, { ok: true, riskScore: 1 }, 200);
      expect(await store.get(key)).toMatchObject({ state: "completed", circleTransferId: "circle-transfer", finalResult: { ok: true, riskScore: 1 } });

      const noNonceReservation = await store.reserve(noNonceKey, noNonceFingerprint, "package");
      expect(noNonceReservation.kind).toBe("created");
      expect(await store.claimPaymentAttempt(noNonceKey, noNonceFingerprint)).toBe(true);
      expect(await store.get(noNonceKey)).toMatchObject({ state: "settling" });
      expect(await store.releasePaymentAttempt(noNonceKey, noNonceFingerprint)).toBe(true);
      expect(await store.get(noNonceKey)).toMatchObject({ state: "waiting_payment" });
      expect(await store.releasePaymentAttempt(noNonceKey, noNonceFingerprint)).toBe(false);
    } finally {
      await setupDb`DELETE FROM paid_requests WHERE idempotency_key IN (${key}, ${noNonceKey})`;
    }
  });
});
