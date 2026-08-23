import { describe, expect, test } from "bun:test";
import {
  ConsistencyReason,
  canonicalAtomicAmount,
  checkX402ChallengeAgainstPreflight,
  type PreflightChallenge
} from "../src/domain/x402-preflight-consistency.ts";
import type { X402EndpointPreflight } from "../src/domain/x402-preflight-consistency.ts";

const RESOURCE = "https://example.com/api/paid";

function preflight(overrides: Partial<X402EndpointPreflight["preflightContext"] & { expiresAt: string | undefined }> = {}): Parameters<typeof checkX402ChallengeAgainstPreflight>[0] {
  const { expiresAt, ...context } = overrides;
  return {
    preflightContext: { resource: RESOURCE, paymentOptions: [], ...context },
    ...(expiresAt === undefined ? {} : { freshness: { oldestEvidenceAt: null as string | null, newestEvidenceAt: null as string | null, expiresAt } })
  };
}

function challenge(overrides: Partial<PreflightChallenge> = {}): PreflightChallenge {
  return {
    resource: RESOURCE,
    scheme: "exact",
    network: "eip155:695569",
    amount: "10000",
    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    payTo: "0xAbCdEf0000000000000000000000000000001234",
    ...overrides
  };
}

function option(partial: Partial<PreflightChallenge>): PreflightChallenge {
  return Object.fromEntries(Object.entries(challenge(partial)).filter(([, v]) => v !== undefined)) as PreflightChallenge;
}

describe("x402 preflight challenge consistency", () => {
  test("A: matches the second of multiple observed payment options", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option({ payTo: "0x1111111111111111111111111111111111111111" }), option({ payTo: "0x2222222222222222222222222222222222222222" })] }),
      challenge({ payTo: "0x2222222222222222222222222222222222222222" })
    );
    expect(result.status).toBe("match");
    expect(result.reasons).toEqual([]);
  });

  test("B: does not combine fields across different options", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({
        paymentOptions: [
          option({ network: "eip155:8453", payTo: "0x1111111111111111111111111111111111111111" }),
          option({ network: "eip155:1", payTo: "0x2222222222222222222222222222222222222222" })
        ]
      }),
      challenge({ network: "eip155:1", payTo: "0x1111111111111111111111111111111111111111" })
    );
    expect(result.status).toBe("repreflight_required");
    expect(result.reasons).toContain(ConsistencyReason.PAYMENT_REQUIREMENTS_MISMATCH);
  });

  test("C: reports an expired preflight before comparing anything else", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ expiresAt: "2026-08-23T10:01:00.000Z", paymentOptions: [option({})] }),
      challenge(),
      new Date("2026-08-23T10:01:00.000Z")
    );
    expect(result.status).toBe("repreflight_required");
    expect(result.reasons).toEqual([ConsistencyReason.PREFLIGHT_EXPIRED]);
  });

  test("D: changed payout destination requires re-preflight", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option({})] }),
      challenge({ payTo: "0x9999999999999999999999999999999999999999" })
    );
    expect(result.status).toBe("repreflight_required");
    expect(result.reasons).toEqual([ConsistencyReason.PAYMENT_REQUIREMENTS_MISMATCH]);
  });

  test("E: changed atomic amount requires re-preflight", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option({})] }),
      challenge({ amount: "20000" })
    );
    expect(result.status).toBe("repreflight_required");
    expect(result.reasons).toEqual([ConsistencyReason.PAYMENT_REQUIREMENTS_MISMATCH]);
  });

  test("F: changed network requires re-preflight", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option({})] }),
      challenge({ network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" })
    );
    expect(result.status).toBe("repreflight_required");
    expect(result.reasons).toEqual([ConsistencyReason.PAYMENT_REQUIREMENTS_MISMATCH]);
  });

  test("G: no observed payment options yields insufficient context, not a mismatch", () => {
    const result = checkX402ChallengeAgainstPreflight(preflight(), challenge());
    expect(result.status).toBe("insufficient_context");
    expect(result.reasons).toEqual([ConsistencyReason.NO_OBSERVED_PAYMENT_OPTIONS]);
  });

  test("H: EVM address casing differences do not create a false mismatch", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option({ payTo: "0xabcdef0000000000000000000000000000001234" })] }),
      challenge()
    );
    expect(result.status).toBe("match");
  });

  test("I: non-EVM identifiers are compared case-sensitively", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [{ scheme: "exact", network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", amount: "10000", payTo: "SoMeBase58AddRess11111111111111111111111111" }] }),
      challenge({ network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", payTo: "somebase58address11111111111111111111111111" })
    );
    expect(result.status).toBe("repreflight_required");
    expect(result.reasons).toEqual([ConsistencyReason.PAYMENT_REQUIREMENTS_MISMATCH]);
  });

  test("resource URL mismatch requires re-preflight", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option({})] }),
      challenge({ resource: `${RESOURCE}?tier=pro` })
    );
    expect(result.status).toBe("repreflight_required");
    expect(result.reasons).toEqual([ConsistencyReason.RESOURCE_MISMATCH]);
  });

  test("challenge missing a field that was observed does not match", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [{ network: "eip155:695569", amount: "10000", payTo: challenge().payTo! }] }),
      challenge()
    );
    expect(result.status).toBe("repreflight_required");
    expect(result.reasons).toEqual([ConsistencyReason.PAYMENT_REQUIREMENTS_MISMATCH]);
  });

  test("amount comparison is exact decimal-string based, never floating point", () => {
    expect(canonicalAtomicAmount("10000")).toBe("10000");
    expect(canonicalAtomicAmount("10000.00")).toBe("10000");
    expect(canonicalAtomicAmount("010000.500")).toBe("10000.5");
    expect(canonicalAtomicAmount("1e3")).toBeUndefined();
    const same = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option({})] }),
      challenge({ amount: "10000.000" })
    );
    expect(same.status).toBe("match");
    const exponent = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option({})] }),
      challenge({ amount: "1e4" })
    );
    expect(exponent.status).toBe("repreflight_required");
    expect(exponent.reasons).toEqual([ConsistencyReason.PAYMENT_REQUIREMENTS_MISMATCH]);
  });
});
