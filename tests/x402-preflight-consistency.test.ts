import { describe, expect, test } from "bun:test";
import { CIRCLE_BATCHING_NAME, CIRCLE_BATCHING_VERSION } from "@circle-fin/x402-batching";
import type { PaymentRequired, PaymentRequirements } from "@x402/core/types";
import {
  ConsistencyReason,
  canonicalAtomicAmount,
  checkX402ChallengeAgainstPreflight,
  type PreflightChallenge,
  type ObservedPaymentRequirement
} from "../src/domain/x402-preflight-consistency.ts";
import { observedPaymentOptions } from "../src/providers/circle-discovery.ts";
import type { X402EndpointPreflight } from "../src/domain/x402-preflight-consistency.ts";

const RESOURCE = "https://example.com/api/paid";
const NETWORK = "eip155:695569";
const ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAY_TO = "0xAbCdEf0000000000000000000000000000001234";
const VERIFYING_CONTRACT = "0x0077777d7EBA4688BDeF3E311b846F25870A19B9";
const GATEWAY_EXTRA = {
  name: CIRCLE_BATCHING_NAME,
  version: CIRCLE_BATCHING_VERSION,
  verifyingContract: VERIFYING_CONTRACT
};

type RequirementOverrides = Partial<PaymentRequirements>;

function requirements(overrides: RequirementOverrides = {}): PaymentRequirements {
  return {
    scheme: "exact",
    network: NETWORK,
    amount: "10000",
    asset: ASSET,
    payTo: PAY_TO,
    maxTimeoutSeconds: 300,
    extra: GATEWAY_EXTRA,
    ...overrides
  };
}

function paymentRequired(selected: PaymentRequirements, resource = RESOURCE): PaymentRequired {
  return {
    x402Version: 2,
    resource: { url: resource },
    accepts: [selected]
  };
}

function challenge(overrides: RequirementOverrides = {}, resource = RESOURCE): PreflightChallenge {
  const selected = requirements(overrides);
  return { paymentRequired: paymentRequired(selected, resource), requirements: selected };
}

function preflight(overrides: Partial<X402EndpointPreflight["preflightContext"] & { expiresAt: string | undefined }> = {}): Parameters<typeof checkX402ChallengeAgainstPreflight>[0] {
  const { expiresAt, ...context } = overrides;
  return {
    preflightContext: { resource: RESOURCE, paymentOptions: [], ...context },
    ...(expiresAt === undefined ? {} : { freshness: { oldestEvidenceAt: null as string | null, newestEvidenceAt: null as string | null, expiresAt } })
  };
}

function option(overrides: Partial<ObservedPaymentRequirement> = {}): ObservedPaymentRequirement {
  return {
    scheme: "exact",
    network: NETWORK,
    amount: "10000",
    asset: ASSET,
    payTo: PAY_TO,
    maxTimeoutSeconds: 300,
    extra: GATEWAY_EXTRA,
    ...overrides
  };
}

function expectMismatch(result: ReturnType<typeof checkX402ChallengeAgainstPreflight>): void {
  expect(result.status).toBe("repreflight_required");
  expect(result.reasons).toEqual([ConsistencyReason.PAYMENT_REQUIREMENTS_MISMATCH]);
}

describe("x402 preflight challenge consistency", () => {
  test("A: exact Circle Gateway metadata and requirements match", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option()] }),
      challenge()
    );
    expect(result).toEqual({ status: "match", reasons: [] });
  });

  test("B: verifyingContract drift or removal requires re-preflight", () => {
    const drifted = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option()] }),
      challenge({ extra: { ...GATEWAY_EXTRA, verifyingContract: "0x1111111111111111111111111111111111111111" } })
    );
    expectMismatch(drifted);

    const missing = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option()] }),
      challenge({ extra: { name: CIRCLE_BATCHING_NAME, version: CIRCLE_BATCHING_VERSION } })
    );
    expectMismatch(missing);
  });

  test("C: removed or changed Gateway name does not match", () => {
    const removed = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option()] }),
      challenge({ extra: {} })
    );
    expectMismatch(removed);

    const changed = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option()] }),
      challenge({ extra: { ...GATEWAY_EXTRA, name: "OtherPayment" } })
    );
    expectMismatch(changed);
  });

  test("D: Gateway version drift requires re-preflight", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option()] }),
      challenge({ extra: { ...GATEWAY_EXTRA, version: "2" } })
    );
    expectMismatch(result);
  });

  test("E: maxTimeoutSeconds drift requires re-preflight", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option()] }),
      challenge({ maxTimeoutSeconds: 301 })
    );
    expectMismatch(result);
  });

  test("F: compares PaymentRequired.resource.url without flattening ResourceInfo", () => {
    const selected = requirements();
    const actual: PreflightChallenge = {
      paymentRequired: {
        x402Version: 2,
        resource: { url: RESOURCE },
        accepts: [selected]
      },
      requirements: selected
    };
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option()] }),
      actual
    );
    expect(result.status).toBe("match");
  });

  test("G: an incomplete observed Gateway option is insufficient context", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [{ scheme: "exact", network: NETWORK, amount: "10000", payTo: PAY_TO }] }),
      challenge()
    );
    expect(result).toEqual({
      status: "insufficient_context",
      reasons: [ConsistencyReason.INSUFFICIENT_PAYMENT_REQUIREMENT_CONTEXT]
    });
  });

  test("H: atomic amounts accept integers and leading zeros only", () => {
    expect(canonicalAtomicAmount("10000")).toBe("10000");
    expect(canonicalAtomicAmount("010000")).toBe("10000");
    expect(canonicalAtomicAmount("10000.00")).toBeUndefined();
    expect(canonicalAtomicAmount("1e4")).toBeUndefined();

    const leadingZero = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option({ amount: "010000" })] }),
      challenge({ amount: "10000" })
    );
    expect(leadingZero.status).toBe("match");

    const decimal = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option({ amount: "10000" })] }),
      challenge({ amount: "10000.00" })
    );
    expectMismatch(decimal);

    const exponent = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option({ amount: "10000" })] }),
      challenge({ amount: "1e4" })
    );
    expectMismatch(exponent);
  });

  test("I: multiple Circle options remain atomic and are never cross-combined", () => {
    const firstPayTo = "0x1111111111111111111111111111111111111111";
    const secondPayTo = "0x2222222222222222222222222222222222222222";
    const result = checkX402ChallengeAgainstPreflight(
      preflight({
        paymentOptions: [
          option({ network: "eip155:8453", payTo: firstPayTo }),
          option({ network: "eip155:1", payTo: secondPayTo })
        ]
      }),
      challenge({ network: "eip155:1", payTo: firstPayTo })
    );
    expectMismatch(result);
  });

  test("empty observed options keep the dedicated no-options reason", () => {
    const result = checkX402ChallengeAgainstPreflight(preflight(), challenge());
    expect(result).toEqual({
      status: "insufficient_context",
      reasons: [ConsistencyReason.NO_OBSERVED_PAYMENT_OPTIONS]
    });
  });

  test("changed payout destination requires re-preflight", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option()] }),
      challenge({ payTo: "0x9999999999999999999999999999999999999999" })
    );
    expectMismatch(result);
  });

  test("changed atomic amount requires re-preflight", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option()] }),
      challenge({ amount: "20000" })
    );
    expectMismatch(result);
  });

  test("changed network requires re-preflight", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option()] }),
      challenge({ network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" })
    );
    expectMismatch(result);
  });

  test("expired preflight is reported before payment comparison", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ expiresAt: "2026-08-23T10:01:00.000Z", paymentOptions: [option()] }),
      challenge(),
      new Date("2026-08-23T10:01:00.000Z")
    );
    expect(result).toEqual({ status: "repreflight_required", reasons: [ConsistencyReason.PREFLIGHT_EXPIRED] });
  });

  test("resource query strings remain distinct", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option()] }),
      challenge({}, `${RESOURCE}?tier=pro`)
    );
    expect(result).toEqual({ status: "repreflight_required", reasons: [ConsistencyReason.RESOURCE_MISMATCH] });
  });

  test("EVM address casing differences do not create a false mismatch", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option({ payTo: PAY_TO.toLowerCase(), extra: { ...GATEWAY_EXTRA, verifyingContract: VERIFYING_CONTRACT.toLowerCase() } })] }),
      challenge()
    );
    expect(result.status).toBe("match");
  });

  test("non-EVM identifiers remain case-sensitive", () => {
    const result = checkX402ChallengeAgainstPreflight(
      preflight({ paymentOptions: [option({ network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", payTo: "SoMeBase58AddRess11111111111111111111111111", extra: {} })] }),
      challenge({ network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", payTo: "somebase58address11111111111111111111111111", extra: {} })
    );
    expectMismatch(result);
  });

  test("observed Discovery options preserve Circle metadata without inventing fields", () => {
    const options = observedPaymentOptions({
      resource: RESOURCE,
      accepts: [{ scheme: "exact", network: NETWORK, amount: "10000", asset: ASSET, payTo: PAY_TO, maxTimeoutSeconds: 300, extra: GATEWAY_EXTRA }]
    });
    expect(options).toEqual([option()]);

    const partial = observedPaymentOptions({ resource: RESOURCE, accepts: [{ scheme: "exact", network: NETWORK }] });
    expect(partial).toEqual([{ scheme: "exact", network: NETWORK }]);
  });
});
