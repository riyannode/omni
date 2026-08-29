import { getVerifyingContract, supportsBatching } from "@circle-fin/x402-batching";
import type { PaymentRequired, PaymentRequirements } from "@x402/core/types";
import type { RiskAssessment } from "./risk.ts";

export type ObservedPaymentRequirement = {
  scheme?: PaymentRequirements["scheme"];
  network?: PaymentRequirements["network"];
  amount?: PaymentRequirements["amount"];
  asset?: PaymentRequirements["asset"];
  payTo?: PaymentRequirements["payTo"];
  maxTimeoutSeconds?: PaymentRequirements["maxTimeoutSeconds"];
  extra?: {
    name?: string;
    version?: string;
    verifyingContract?: string;
  };
};

export type X402EndpointPreflight = RiskAssessment & {
  preflightContext: {
    resource: string;
    paymentOptions: ObservedPaymentRequirement[];
  };
};

function observedGatewayExtra(extra: unknown): ObservedPaymentRequirement["extra"] {
  if (typeof extra !== "object" || extra === null || Array.isArray(extra)) return undefined;
  const value = extra as Record<string, unknown>;
  const name = typeof value.name === "string" ? value.name : undefined;
  const version = typeof value.version === "string" ? value.version : undefined;
  const verifyingContract = typeof value.verifyingContract === "string" ? value.verifyingContract : undefined;
  if (name === undefined && version === undefined && verifyingContract === undefined) return undefined;
  return {
    ...(name === undefined ? {} : { name }),
    ...(version === undefined ? {} : { version }),
    ...(verifyingContract === undefined ? {} : { verifyingContract })
  };
}

export function observePaymentOptions(rawAccepts: unknown): ObservedPaymentRequirement[] {
  if (!Array.isArray(rawAccepts)) return [];
  return rawAccepts.map(rawAccept => {
    if (typeof rawAccept !== "object" || rawAccept === null || Array.isArray(rawAccept)) return {};
    const accept = rawAccept as Record<string, unknown>;
    const observed: ObservedPaymentRequirement = {};
    if (typeof accept.scheme === "string") observed.scheme = accept.scheme as NonNullable<ObservedPaymentRequirement["scheme"]>;
    if (typeof accept.network === "string") observed.network = accept.network as NonNullable<ObservedPaymentRequirement["network"]>;
    if (typeof accept.amount === "string") observed.amount = accept.amount as NonNullable<ObservedPaymentRequirement["amount"]>;
    if (typeof accept.asset === "string") observed.asset = accept.asset as NonNullable<ObservedPaymentRequirement["asset"]>;
    if (typeof accept.payTo === "string") observed.payTo = accept.payTo as NonNullable<ObservedPaymentRequirement["payTo"]>;
    if (typeof accept.maxTimeoutSeconds === "number") observed.maxTimeoutSeconds = accept.maxTimeoutSeconds;
    const extra = observedGatewayExtra(accept.extra);
    if (extra !== undefined) observed.extra = extra;
    return observed;
  });
}

export type ChallengeConsistencyStatus = "match" | "repreflight_required" | "insufficient_context";

/**
 * Stable machine-readable reason codes. They describe consistency with the
 * observed preflight configuration, never authorization.
 */
export const ConsistencyReason = {
  PREFLIGHT_EXPIRED: "PREFLIGHT_EXPIRED",
  RESOURCE_MISMATCH: "RESOURCE_MISMATCH",
  PAYMENT_REQUIREMENTS_MISMATCH: "PAYMENT_REQUIREMENTS_MISMATCH",
  NO_OBSERVED_PAYMENT_OPTIONS: "NO_OBSERVED_PAYMENT_OPTIONS",
  INSUFFICIENT_PAYMENT_REQUIREMENT_CONTEXT: "INSUFFICIENT_PAYMENT_REQUIREMENT_CONTEXT",
  SELECTED_REQUIREMENT_NOT_OFFERED: "SELECTED_REQUIREMENT_NOT_OFFERED"
} as const;

export type PreflightChallenge = {
  paymentRequired: PaymentRequired;
  requirements: PaymentRequirements;
};

export type ConsistencyCheck = {
  status: ChallengeConsistencyStatus;
  reasons: string[];
};

/** EVM hex addresses compare case-insensitively; other identifiers stay case-sensitive. */
export function samePaymentIdentifier(networkPrefix: string, a: string, b: string): boolean {
  if (a === b) return true;
  return networkPrefix.startsWith("eip155:") && /^0x[0-9a-fA-F]{40}$/.test(a) && /^0x[0-9a-fA-F]{40}$/.test(b)
    ? a.toLowerCase() === b.toLowerCase()
    : false;
}

function sameField(field: "asset" | "payTo" | "verifyingContract", network: string | undefined, a: string, b: string): boolean {
  return field === "payTo" || field === "asset" || field === "verifyingContract" ? samePaymentIdentifier(network ?? "", a, b) : a === b;
}

/**
 * Canonical comparison for x402 atomic-unit amount strings. Only plain,
 * non-negative decimal integers are valid; leading zeros are normalized, but
 * decimal fractions and exponent notation are never accepted.
 */
export function canonicalAtomicAmount(value: string): string | undefined {
  return /^\d+$/.test(value) ? value.replace(/^0+(?=\d)/, "") : undefined;
}

function amountsMatch(a: string, b: string): boolean {
  const canonicalA = canonicalAtomicAmount(a);
  const canonicalB = canonicalAtomicAmount(b);
  return canonicalA !== undefined && canonicalA === canonicalB;
}

const genericFields = ["scheme", "network", "amount", "asset", "payTo"] as const;
const gatewayFields = ["name", "version", "verifyingContract"] as const;

function observedGatewayValue(observed: ObservedPaymentRequirement, field: (typeof gatewayFields)[number]): string | undefined {
  return observed.extra?.[field];
}

function actualGatewayValue(requirements: PaymentRequirements, field: (typeof gatewayFields)[number]): string | undefined {
  if (field === "verifyingContract") {
    const verifyingContract = getVerifyingContract(requirements);
    if (verifyingContract !== undefined) return verifyingContract;
  }
  const value = requirements.extra[field];
  return typeof value === "string" ? value : undefined;
}

function requirementsMatch(a: PaymentRequirements, b: PaymentRequirements): boolean {
  for (const field of genericFields) {
    const left = a[field];
    const right = b[field];
    if (field === "amount") {
      if (left !== right && !amountsMatch(left, right)) return false;
    } else if (field === "asset" || field === "payTo") {
      if (!sameField(field, a.network, left, right)) return false;
    } else if (left !== right) return false;
  }
  if (a.maxTimeoutSeconds !== b.maxTimeoutSeconds) return false;

  for (const field of gatewayFields) {
    const left = actualGatewayValue(a, field);
    const right = actualGatewayValue(b, field);
    if (left === undefined && right === undefined) continue;
    if (left === undefined || right === undefined) return false;
    if (field === "verifyingContract" ? !sameField(field, a.network, left, right) : left !== right) return false;
  }
  return true;
}

function hasGenericContext(observed: ObservedPaymentRequirement): boolean {
  return genericFields.every(field => observed[field] !== undefined) && observed.maxTimeoutSeconds !== undefined;
}

function hasCircleGatewayContext(observed: ObservedPaymentRequirement): boolean {
  return gatewayFields.every(field => observedGatewayValue(observed, field) !== undefined);
}

function hasEnoughContext(observed: ObservedPaymentRequirement, actual: PaymentRequirements): boolean {
  return hasGenericContext(observed) && (!supportsBatching(actual) || hasCircleGatewayContext(observed));
}

function optionMatches(observed: ObservedPaymentRequirement, challenge: PreflightChallenge): boolean {
  const requirements = challenge.requirements;
  for (const field of genericFields) {
    const seen = observed[field];
    const actual = requirements[field];
    if (seen === undefined) return false;
    if (field === "amount") {
      if (!amountsMatch(seen, actual)) return false;
    } else if (field === "asset" || field === "payTo") {
      if (!sameField(field, observed.network, seen, actual)) return false;
    } else if (seen !== actual) return false;
  }
  if (observed.maxTimeoutSeconds !== requirements.maxTimeoutSeconds) return false;

  for (const field of gatewayFields) {
    const seen = observedGatewayValue(observed, field);
    if (seen === undefined) continue;
    const actual = actualGatewayValue(requirements, field);
    if (actual === undefined) return false;
    if (field === "verifyingContract" ? !sameField(field, requirements.network, seen, actual) : seen !== actual) return false;
  }
  return true;
}

/**
 * Pure local check of an actual x402 PaymentRequirements selection against the
 * configuration OMNI observed during preflight.
 *
 * Advisory and consistency-only: it performs no I/O, touches no wallet, and
 * its result neither authorizes nor blocks any payment. `recommendation` and
 * `riskScore` remain RiskEngine outputs and are deliberately not consulted.
 */
export function checkX402ChallengeAgainstPreflight(
  preflight: {
    preflightContext: X402EndpointPreflight["preflightContext"];
    freshness?: RiskAssessment["freshness"];
  },
  challenge: PreflightChallenge,
  now: Date = new Date()
): ConsistencyCheck {
  const reasons: string[] = [];
  const expiresAt = preflight.freshness?.expiresAt;

  if (expiresAt !== undefined && now.getTime() >= Date.parse(expiresAt)) {
    return { status: "repreflight_required", reasons: [ConsistencyReason.PREFLIGHT_EXPIRED] };
  }

  const assessedResource = preflight.preflightContext.resource;
  if (challenge.paymentRequired.resource.url !== assessedResource) {
    return { status: "repreflight_required", reasons: [ConsistencyReason.RESOURCE_MISMATCH] };
  }

  if (!challenge.paymentRequired.accepts.some(offered => requirementsMatch(challenge.requirements, offered))) {
    return { status: "repreflight_required", reasons: [ConsistencyReason.SELECTED_REQUIREMENT_NOT_OFFERED] };
  }

  const options = preflight.preflightContext.paymentOptions;
  if (options.length === 0) {
    return { status: "insufficient_context", reasons: [ConsistencyReason.NO_OBSERVED_PAYMENT_OPTIONS] };
  }

  const comparableOptions = options.filter(option => hasEnoughContext(option, challenge.requirements));
  if (comparableOptions.length === 0) {
    return { status: "insufficient_context", reasons: [ConsistencyReason.INSUFFICIENT_PAYMENT_REQUIREMENT_CONTEXT] };
  }

  if (comparableOptions.some(option => optionMatches(option, challenge))) return { status: "match", reasons: [] };

  return { status: "repreflight_required", reasons: [ConsistencyReason.PAYMENT_REQUIREMENTS_MISMATCH] };
}
