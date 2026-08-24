import type { PaymentRequirements } from "@x402/core/types";
import type { Recommendation, RiskAssessment } from "./domain/risk.ts";
import {
  canonicalAtomicAmount,
  type ConsistencyCheck,
  type X402EndpointPreflight
} from "./domain/x402-preflight-consistency.ts";
import { samePaymentIdentifier } from "./domain/x402-preflight-consistency.ts";

export type PurchaseDecisionStatus = "ALLOW" | "DENY" | "RE_PREFLIGHT" | "MANUAL_REVIEW";

export const BuyerPolicyReason = {
  CONSISTENCY_REQUIRES_PREFLIGHT: "CONSISTENCY_REQUIRES_PREFLIGHT",
  CONSISTENCY_INSUFFICIENT_CONTEXT: "CONSISTENCY_INSUFFICIENT_CONTEXT",
  RECOMMENDATION_DO_NOT_PROCEED: "RECOMMENDATION_DO_NOT_PROCEED",
  RECOMMENDATION_MANUAL_REVIEW: "RECOMMENDATION_MANUAL_REVIEW",
  RECOMMENDATION_NOT_ALLOWED: "RECOMMENDATION_NOT_ALLOWED",
  EVIDENCE_COVERAGE_TOO_LOW: "EVIDENCE_COVERAGE_TOO_LOW",
  NETWORK_NOT_ALLOWED: "NETWORK_NOT_ALLOWED",
  ASSET_NOT_ALLOWED: "ASSET_NOT_ALLOWED",
  AMOUNT_INVALID: "AMOUNT_INVALID",
  MAXIMUM_AMOUNT_INVALID: "MAXIMUM_AMOUNT_INVALID",
  AMOUNT_EXCEEDS_LIMIT: "AMOUNT_EXCEEDS_LIMIT"
} as const;

export type BuyerPolicy = {
  allowedRecommendations: readonly Recommendation[];
  minimumEvidenceCoverage: number;
  allowedNetworks: readonly string[];
  allowedAssets: readonly string[];
  maximumAtomicAmount: string;
};

export type PurchaseDecision = {
  status: PurchaseDecisionStatus;
  reasons: string[];
};

export type PurchaseEvaluation = {
  preflight: X402EndpointPreflight;
  consistency: ConsistencyCheck;
  requirements: PaymentRequirements;
  policy: BuyerPolicy;
};

function decision(status: PurchaseDecisionStatus, ...reasons: string[]): PurchaseDecision {
  return { status, reasons };
}

/**
 * Evaluates caller-owned purchase conditions after OMNI consistency checking.
 * This module is pure: it does not sign, settle, access wallet state, or perform I/O.
 */
export function evaluatePurchase(input: PurchaseEvaluation): PurchaseDecision {
  void input.preflight;

  if (input.consistency.status === "repreflight_required") {
    return decision("RE_PREFLIGHT", BuyerPolicyReason.CONSISTENCY_REQUIRES_PREFLIGHT);
  }
  if (input.consistency.status === "insufficient_context") {
    return decision("RE_PREFLIGHT", BuyerPolicyReason.CONSISTENCY_INSUFFICIENT_CONTEXT);
  }

  const recommendation = input.preflight.recommendation;
  if (recommendation === "do_not_proceed") {
    return decision("DENY", BuyerPolicyReason.RECOMMENDATION_DO_NOT_PROCEED);
  }
  if (recommendation === "manual_review") {
    return decision("MANUAL_REVIEW", BuyerPolicyReason.RECOMMENDATION_MANUAL_REVIEW);
  }
  if (!input.policy.allowedRecommendations.includes(recommendation)) {
    return decision("DENY", BuyerPolicyReason.RECOMMENDATION_NOT_ALLOWED);
  }

  if (!Number.isFinite(input.preflight.evidenceCoverage) || input.preflight.evidenceCoverage < input.policy.minimumEvidenceCoverage) {
    return decision("MANUAL_REVIEW", BuyerPolicyReason.EVIDENCE_COVERAGE_TOO_LOW);
  }
  if (!input.policy.allowedNetworks.includes(input.requirements.network)) {
    return decision("DENY", BuyerPolicyReason.NETWORK_NOT_ALLOWED);
  }
  if (!input.policy.allowedAssets.some(asset => samePaymentIdentifier(input.requirements.network, input.requirements.asset, asset))) {
    return decision("DENY", BuyerPolicyReason.ASSET_NOT_ALLOWED);
  }

  const amount = canonicalAtomicAmount(input.requirements.amount);
  if (amount === undefined) return decision("DENY", BuyerPolicyReason.AMOUNT_INVALID);

  const maximum = canonicalAtomicAmount(input.policy.maximumAtomicAmount);
  if (maximum === undefined) return decision("DENY", BuyerPolicyReason.MAXIMUM_AMOUNT_INVALID);
  if (BigInt(amount) > BigInt(maximum)) return decision("DENY", BuyerPolicyReason.AMOUNT_EXCEEDS_LIMIT);

  return decision("ALLOW");
}
