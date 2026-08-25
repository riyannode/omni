import { afterEach, describe, expect, test } from "bun:test";
import { createServer, type Server } from "node:http";
import type { PaymentRequirements } from "@x402/core/types";
import type { RiskAssessment } from "../src/domain/risk.ts";
import type { X402EndpointPreflight } from "../src/domain/x402-preflight-consistency.ts";
import { runX402Buyer, type X402BuyerOptions } from "../src/x402-buyer.ts";
import type { BuyerPolicy } from "../src/buyer-policy.ts";

const NETWORK = "eip155:695569";
const ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAY_TO = "0xAbCdEf0000000000000000000000000000001234";
const servers: Server[] = [];

function requirements(overrides: Partial<PaymentRequirements> = {}): PaymentRequirements {
  return {
    scheme: "exact",
    network: NETWORK,
    amount: "10000",
    asset: ASSET,
    payTo: PAY_TO,
    maxTimeoutSeconds: 300,
    extra: {},
    ...overrides
  };
}

function assessment(overrides: Partial<RiskAssessment> = {}): RiskAssessment {
  return {
    subject: { type: "x402_endpoint", id: "pending" },
    policyVersion: "test-policy",
    recommendation: "proceed",
    riskScore: 5,
    evidenceCoverage: 1,
    dimensions: {
      knownVulnerabilities: "low",
      knownExploitation: "low",
      packageSupplyChain: "unknown",
      repositorySecurityPractices: "unknown",
      maliciousInfrastructure: "low",
      serviceIdentity: "low",
      paymentConfigurationRisk: "low",
      endpointOperationalRisk: "low"
    },
    signals: [],
    evidence: [],
    sourceErrors: [],
    assessedAt: "2026-08-24T00:00:00.000Z",
    freshness: { oldestEvidenceAt: null, newestEvidenceAt: null, expiresAt: "2099-01-01T00:00:00.000Z" },
    ...overrides
  };
}

function buyerPolicy(): BuyerPolicy {
  return {
    allowedRecommendations: ["proceed", "proceed_with_caution"],
    minimumEvidenceCoverage: 0.8,
    allowedNetworks: [NETWORK],
    allowedAssets: [ASSET],
    maximumAtomicAmount: "10000"
  };
}

function preflight(resource: string, option: PaymentRequirements, overrides: Partial<RiskAssessment> = {}): X402EndpointPreflight {
  return {
    ...assessment({ ...overrides, subject: { type: "x402_endpoint", id: resource } }),
    preflightContext: { resource, paymentOptions: [option] }
  };
}

async function startTarget(accepts: PaymentRequirements[], resource: () => string, paymentRequiredOverride?: unknown): Promise<{ url: string; close: () => Promise<void> }> {
  const server = createServer((_request, response) => {
    const paymentRequired = paymentRequiredOverride ?? {
      x402Version: 2,
      resource: { url: resource() },
      accepts
    };
    response.writeHead(402, {
      "content-type": "application/json",
      "payment-required": Buffer.from(JSON.stringify(paymentRequired)).toString("base64")
    });
    response.end(JSON.stringify({ error: "payment required" }));
  });
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("listening", () => resolve());
    server.once("error", reject);
    server.listen(0, "127.0.0.1");
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("target server has no TCP address");
  const url = `http://127.0.0.1:${address.port}/paid`;
  return { url, close: () => new Promise<void>(resolve => server.close(() => resolve())) };
}

async function expectMalformedPaymentRequired(paymentRequired: unknown): Promise<void> {
  const target = await startTarget([], () => target.url, paymentRequired);
  let selectorCalls = 0;
  let paymentCalls = 0;

  const result = await runX402Buyer(target.url, {
    getPreflight: async resource => preflight(resource, requirements()),
    selectPaymentRequirements: accepts => {
      selectorCalls += 1;
      return accepts[0];
    },
    policy: buyerPolicy(),
    payTarget: async () => {
      paymentCalls += 1;
      return new Response("unexpected", { status: 200 });
    }
  });

  expect(result.decision.status).toBe("DENY");
  expect(result.decision.reasons).toContain("INVALID_PAYMENT_REQUIRED");
  expect(selectorCalls).toBe(0);
  expect(paymentCalls).toBe(0);
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))));
});

describe("reference x402 buyer flow", () => {
  test("malformed 402 with accepts [{}] is denied before selection", async () => {
    await expectMalformedPaymentRequired({
      x402Version: 2,
      resource: { url: "https://target.example/paid" },
      accepts: [{}]
    });
  });

  test("malformed 402 with missing resource.url is denied before selection", async () => {
    await expectMalformedPaymentRequired({
      x402Version: 2,
      resource: {},
      accepts: [requirements()]
    });
  });

  test("malformed 402 requirement field is denied before selection", async () => {
    await expectMalformedPaymentRequired({
      x402Version: 2,
      resource: { url: "https://target.example/paid" },
      accepts: [{ ...requirements(), amount: 10000 }]
    });
  });

  test("malformed 402 null extra is denied before selection", async () => {
    await expectMalformedPaymentRequired({
      x402Version: 2,
      resource: { url: "https://target.example/paid" },
      accepts: [{ ...requirements(), extra: null }]
    });
  });

  test("malformed 402 array extra is denied before selection", async () => {
    await expectMalformedPaymentRequired({
      x402Version: 2,
      resource: { url: "https://target.example/paid" },
      accepts: [{ ...requirements(), extra: [] }]
    });
  });

  test("Flow A: matching actual 402 reaches ALLOW and calls payment once", async () => {
    const offered = requirements();
    const target = await startTarget([offered], () => target.url);
    let preflightCalls = 0;
    let paymentCalls = 0;
    const options: X402BuyerOptions = {
      getPreflight: async resource => {
        preflightCalls += 1;
        return preflight(resource, offered);
      },
      selectPaymentRequirements: accepts => accepts[0],
      policy: buyerPolicy(),
      payTarget: async input => {
        paymentCalls += 1;
        expect(input.requirements).toBe(input.paymentRequired.accepts[0]!);
        return new Response(JSON.stringify({ paid: true }), { status: 200 });
      }
    };

    const result = await runX402Buyer(target.url, options);

    expect(preflightCalls).toBe(1);
    expect(result.requirements).toEqual(offered);
    expect(result.requirements).toBe(result.paymentRequired?.accepts[0]);
    expect(result.decision).toEqual({ status: "ALLOW", reasons: [] });
    expect(paymentCalls).toBe(1);
  });

  test("Flow B: changed actual requirements require re-preflight and never pay", async () => {
    const observed = requirements();
    const changed = requirements({ amount: "10001" });
    const target = await startTarget([changed], () => target.url);
    let paymentCalls = 0;

    const result = await runX402Buyer(target.url, {
      getPreflight: async resource => preflight(resource, observed),
      selectPaymentRequirements: accepts => accepts[0],
      policy: buyerPolicy(),
      payTarget: async () => {
        paymentCalls += 1;
        return new Response("unexpected", { status: 200 });
      }
    });

    expect(result.consistency?.status).toBe("repreflight_required");
    expect(result.decision.status).toBe("RE_PREFLIGHT");
    expect(paymentCalls).toBe(0);
  });

  test("Flow C: manual-review recommendation never pays", async () => {
    const offered = requirements();
    const target = await startTarget([offered], () => target.url);
    let paymentCalls = 0;

    const result = await runX402Buyer(target.url, {
      getPreflight: async resource => preflight(resource, offered, { recommendation: "manual_review" }),
      selectPaymentRequirements: accepts => accepts[0],
      policy: buyerPolicy(),
      payTarget: async () => {
        paymentCalls += 1;
        return new Response("unexpected", { status: 200 });
      }
    });

    expect(result.consistency?.status).toBe("match");
    expect(result.decision.status).toBe("MANUAL_REVIEW");
    expect(paymentCalls).toBe(0);
  });
});
