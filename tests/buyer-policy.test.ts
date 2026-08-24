import { describe, expect, test } from "bun:test";
import type { PaymentRequirements } from "@x402/core/types";
import type { RiskAssessment } from "../src/domain/risk.ts";
import type {
  ChallengeConsistencyStatus,
  ConsistencyCheck,
  X402EndpointPreflight
} from "../src/domain/x402-preflight-consistency.ts";
import {
  BuyerPolicyReason,
  evaluatePurchase,
  type BuyerPolicy,
  type PurchaseDecisionStatus
} from "../src/buyer-policy.ts";

const RESOURCE = "https://target.example/paid";
const NETWORK = "eip155:695569";
const ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAY_TO = "0xAbCdEf0000000000000000000000000000001234";

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

function preflight(overrides: Partial<RiskAssessment> = {}): X402EndpointPreflight {
  return {
    subject: { type: "x402_endpoint", id: RESOURCE },
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
    freshness: { oldestEvidenceAt: null, newestEvidenceAt: null, expiresAt: "2026-08-25T00:00:00.000Z" },
    preflightContext: { resource: RESOURCE, paymentOptions: [] },
    ...overrides
  };
}

function consistency(status: ChallengeConsistencyStatus = "match", reasons: string[] = []): ConsistencyCheck {
  return { status, reasons };
}

function policy(overrides: Partial<BuyerPolicy> = {}): BuyerPolicy {
  return {
    allowedRecommendations: ["proceed", "proceed_with_caution"],
    minimumEvidenceCoverage: 0.8,
    allowedNetworks: [NETWORK],
    allowedAssets: [ASSET],
    maximumAtomicAmount: "10000",
    ...overrides
  };
}

function decision(overrides: {
  assessment?: Partial<RiskAssessment>;
  consistency?: ConsistencyCheck;
  requirements?: Partial<PaymentRequirements>;
  policy?: Partial<BuyerPolicy>;
} = {}) {
  return evaluatePurchase({
    preflight: preflight(overrides.assessment),
    consistency: overrides.consistency ?? consistency(),
    requirements: requirements(overrides.requirements),
    policy: policy(overrides.policy)
  });
}

function expectStatus(result: ReturnType<typeof evaluatePurchase>, status: PurchaseDecisionStatus, reason: string): void {
  expect(result.status).toBe(status);
  expect(result.reasons).toContain(reason);
}

describe("caller-side x402 purchase policy", () => {
  test("matching requirements and accepted recommendation allow purchase", () => {
    expect(decision()).toEqual({ status: "ALLOW", reasons: [] });
  });

  test("repreflight_required never allows payment", () => {
    const result = decision({ consistency: consistency("repreflight_required", ["PAYMENT_REQUIREMENTS_MISMATCH"]) });
    expectStatus(result, "RE_PREFLIGHT", BuyerPolicyReason.CONSISTENCY_REQUIRES_PREFLIGHT);
  });

  test("insufficient_context never counts as a match", () => {
    const result = decision({ consistency: consistency("insufficient_context", ["INSUFFICIENT_PAYMENT_REQUIREMENT_CONTEXT"]) });
    expectStatus(result, "RE_PREFLIGHT", BuyerPolicyReason.CONSISTENCY_INSUFFICIENT_CONTEXT);
  });

  test("do_not_proceed is always DENY", () => {
    const result = decision({ assessment: { recommendation: "do_not_proceed" }, policy: { allowedRecommendations: ["do_not_proceed"] } });
    expectStatus(result, "DENY", BuyerPolicyReason.RECOMMENDATION_DO_NOT_PROCEED);
  });

  test("manual_review requires manual review", () => {
    const result = decision({ assessment: { recommendation: "manual_review" } });
    expectStatus(result, "MANUAL_REVIEW", BuyerPolicyReason.RECOMMENDATION_MANUAL_REVIEW);
  });

  test("recommendation outside caller allowlist is denied", () => {
    const result = decision({ assessment: { recommendation: "proceed_with_caution" }, policy: { allowedRecommendations: ["proceed"] } });
    expectStatus(result, "DENY", BuyerPolicyReason.RECOMMENDATION_NOT_ALLOWED);
  });

  test("low evidence coverage requires manual review", () => {
    const result = decision({ assessment: { evidenceCoverage: 0.79 } });
    expectStatus(result, "MANUAL_REVIEW", BuyerPolicyReason.EVIDENCE_COVERAGE_TOO_LOW);
  });

  test("disallowed network is denied", () => {
    const result = decision({ requirements: { network: "eip155:1" } });
    expectStatus(result, "DENY", BuyerPolicyReason.NETWORK_NOT_ALLOWED);
  });

  test("disallowed asset is denied", () => {
    const result = decision({ requirements: { asset: "0x1111111111111111111111111111111111111111" } });
    expectStatus(result, "DENY", BuyerPolicyReason.ASSET_NOT_ALLOWED);
  });

  test("amount above maximum is denied", () => {
    const result = decision({ requirements: { amount: "10001" } });
    expectStatus(result, "DENY", BuyerPolicyReason.AMOUNT_EXCEEDS_LIMIT);
  });

  test("malformed atomic amount is denied", () => {
    for (const amount of ["10000.00", "1e4", "-1", ""]) {
      const result = decision({ requirements: { amount } });
      expectStatus(result, "DENY", BuyerPolicyReason.AMOUNT_INVALID);
    }
  });

  test("leading-zero atomic amount compares canonically without floating point", () => {
    expect(decision({ requirements: { amount: "010000" } })).toEqual({ status: "ALLOW", reasons: [] });
  });

  test("invalid evidence coverage is denied", () => {
    for (const evidenceCoverage of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -0.01, 1.01]) {
      const result = decision({ assessment: { evidenceCoverage } });
      expectStatus(result, "DENY", BuyerPolicyReason.EVIDENCE_COVERAGE_INVALID);
    }
  });

  test("invalid minimum evidence threshold is denied", () => {
    for (const minimumEvidenceCoverage of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -0.01, 1.01]) {
      const result = decision({ policy: { minimumEvidenceCoverage } });
      expectStatus(result, "DENY", BuyerPolicyReason.POLICY_INVALID);
    }
  });
});
