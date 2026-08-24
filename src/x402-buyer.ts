import { x402Client, x402HTTPClient } from "@x402/core/client";
import type { PaymentRequired, PaymentRequirements } from "@x402/core/types";
import {
  checkX402ChallengeAgainstPreflight,
  type ConsistencyCheck,
  type X402EndpointPreflight
} from "./domain/x402-preflight-consistency.ts";
import {
  evaluatePurchase,
  type BuyerPolicy,
  type PurchaseDecision
} from "./buyer-policy.ts";

export const X402BuyerReason = {
  TARGET_DID_NOT_RETURN_402: "TARGET_DID_NOT_RETURN_402",
  INVALID_PAYMENT_REQUIRED: "INVALID_PAYMENT_REQUIRED",
  NO_PAYMENT_REQUIREMENT_SELECTED: "NO_PAYMENT_REQUIREMENT_SELECTED",
  SELECTED_REQUIREMENT_NOT_OFFERED: "SELECTED_REQUIREMENT_NOT_OFFERED"
} as const;

export type GetPreflight = (target: string) => Promise<X402EndpointPreflight>;
export type SelectPaymentRequirements = (accepts: readonly PaymentRequirements[]) => PaymentRequirements | undefined;
export type PayTarget = (input: {
  target: string;
  paymentRequired: PaymentRequired;
  requirements: PaymentRequirements;
}) => Promise<Response>;

export type X402BuyerOptions = {
  getPreflight: GetPreflight;
  selectPaymentRequirements: SelectPaymentRequirements;
  policy: BuyerPolicy;
  payTarget: PayTarget;
  fetch?: typeof fetch;
  now?: Date;
};

export type X402BuyerResult = {
  target: string;
  preflight: X402EndpointPreflight;
  paymentRequired?: PaymentRequired;
  requirements?: PaymentRequirements;
  consistency?: ConsistencyCheck;
  decision: PurchaseDecision;
  paymentResponse?: Response;
};

function result(
  target: string,
  preflight: X402EndpointPreflight,
  decision: PurchaseDecision,
  details: {
    paymentRequired?: PaymentRequired;
    requirements?: PaymentRequirements;
    consistency?: ConsistencyCheck;
    paymentResponse?: Response;
  } = {}
): X402BuyerResult {
  return {
    target,
    preflight,
    decision,
    ...(details.paymentRequired === undefined ? {} : { paymentRequired: details.paymentRequired }),
    ...(details.requirements === undefined ? {} : { requirements: details.requirements }),
    ...(details.consistency === undefined ? {} : { consistency: details.consistency }),
    ...(details.paymentResponse === undefined ? {} : { paymentResponse: details.paymentResponse })
  };
}

function isPaymentRequired(value: unknown): value is PaymentRequired {
  return typeof value === "object" && value !== null && "accepts" in value && Array.isArray(value.accepts);
}

/**
 * Reference caller flow for an external x402 target.
 *
 * `getPreflight` is caller-supplied because acquiring OMNI's existing paid
 * preflight may itself require the separate OMNI bootstrap payment. `payTarget`
 * is the external target payment layer and is invoked only after `ALLOW`.
 */
export async function runX402Buyer(target: string, options: X402BuyerOptions): Promise<X402BuyerResult> {
  const preflight = await options.getPreflight(target);
  const fetchTarget = options.fetch ?? globalThis.fetch;
  const response = await fetchTarget(target, { method: "GET", redirect: "manual" });

  if (response.status !== 402) {
    await response.body?.cancel();
    return result(target, preflight, { status: "DENY", reasons: [X402BuyerReason.TARGET_DID_NOT_RETURN_402] });
  }

  const httpClient = new x402HTTPClient(new x402Client());
  let paymentRequired: PaymentRequired;
  try {
    const parsed = await httpClient.processResponse(response);
    if (parsed.paymentStatus !== "payment_required" || !isPaymentRequired(parsed.header)) {
      return result(target, preflight, { status: "DENY", reasons: [X402BuyerReason.INVALID_PAYMENT_REQUIRED] });
    }
    paymentRequired = parsed.header;
  } catch {
    return result(target, preflight, { status: "DENY", reasons: [X402BuyerReason.INVALID_PAYMENT_REQUIRED] });
  }

  const requirements = options.selectPaymentRequirements(paymentRequired.accepts);
  if (requirements === undefined) {
    return result(target, preflight, { status: "DENY", reasons: [X402BuyerReason.NO_PAYMENT_REQUIREMENT_SELECTED] }, { paymentRequired });
  }
  if (!paymentRequired.accepts.some(offered => offered === requirements)) {
    return result(target, preflight, { status: "DENY", reasons: [X402BuyerReason.SELECTED_REQUIREMENT_NOT_OFFERED] }, { paymentRequired, requirements });
  }

  const consistency = checkX402ChallengeAgainstPreflight(
    preflight,
    { paymentRequired, requirements },
    options.now ?? new Date()
  );
  const decision = evaluatePurchase({ preflight, consistency, requirements, policy: options.policy });
  if (decision.status !== "ALLOW") {
    return result(target, preflight, decision, { paymentRequired, requirements, consistency });
  }

  const paymentResponse = await options.payTarget({ target, paymentRequired, requirements });
  return result(target, preflight, decision, { paymentRequired, requirements, consistency, paymentResponse });
}
