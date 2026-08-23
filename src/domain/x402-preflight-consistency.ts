import type { RiskAssessment } from "./risk.ts";
import type { ObservedPaymentRequirement } from "../providers/circle-discovery.ts";

export type { ObservedPaymentRequirement };

export type X402EndpointPreflight = RiskAssessment & {
  preflightContext: {
    resource: string;
    paymentOptions: ObservedPaymentRequirement[];
  };
};

export type ChallengeConsistencyStatus = "match" | "repreflight_required" | "insufficient_context";

/**
 * Stable machine-readable reason codes. They describe consistency with the
 * observed preflight configuration, never authorization.
 */
export const ConsistencyReason = {
  PREFLIGHT_EXPIRED: "PREFLIGHT_EXPIRED",
  RESOURCE_MISMATCH: "RESOURCE_MISMATCH",
  PAYMENT_REQUIREMENTS_MISMATCH: "PAYMENT_REQUIREMENTS_MISMATCH",
  NO_OBSERVED_PAYMENT_OPTIONS: "NO_OBSERVED_PAYMENT_OPTIONS"
} as const;

export type PreflightChallenge = {
  resource?: string;
  scheme?: string;
  network?: string;
  amount?: string;
  asset?: string;
  payTo?: string;
};

export type ConsistencyCheck = {
  status: ChallengeConsistencyStatus;
  reasons: string[];
};

/** EVM hex addresses compare case-insensitively; other identifiers stay case-sensitive. */
function sameIdentifier(networkPrefix: string, a: string, b: string): boolean {
  if (a === b) return true;
  return networkPrefix.startsWith("eip155:") && /^0x[0-9a-fA-F]{40}$/.test(a) && /^0x[0-9a-fA-F]{40}$/.test(b)
    ? a.toLowerCase() === b.toLowerCase()
    : false;
}

function sameField(field: keyof ObservedPaymentRequirement, network: string | undefined, a: string, b: string): boolean {
  return field === "payTo" || field === "asset" ? sameIdentifier(network ?? "", a, b) : a === b;
}

/**
 * Canonical numeric comparison for atomic-unit amount strings. Decimal strings
 * only — no floating point. Returns undefined when either input is not a plain
 * decimal integer/decimal string so callers fall back to exact string equality.
 */
export function canonicalAtomicAmount(value: string): string | undefined {
  if (!/^\d+(\.\d+)?$/.test(value)) return undefined;
  const [whole = "", fraction = ""] = value.split(".");
  const trimmedWhole = whole.replace(/^0+(?=\d)/, "");
  const trimmedFraction = fraction.replace(/0+$/, "");
  return trimmedFraction === "" ? trimmedWhole : `${trimmedWhole}.${trimmedFraction}`;
}

function amountsMatch(a: string, b: string): boolean {
  return a === b || (canonicalAtomicAmount(a) !== undefined && canonicalAtomicAmount(a) === canonicalAtomicAmount(b));
}

function optionMatches(observed: ObservedPaymentRequirement, challenge: PreflightChallenge): boolean {
  for (const field of ["scheme", "network", "amount", "asset", "payTo"] as const) {
    const seen = observed[field];
    const actual = challenge[field];
    if (seen === undefined && actual === undefined) continue;
    // A field OMNI never observed cannot be confirmed; treat it as unmatched.
    if (seen === undefined || actual === undefined) return false;
    if (field === "amount" ? !amountsMatch(seen, actual) : !sameField(field, observed.network, seen, actual)) return false;
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
  if (challenge.resource !== undefined && challenge.resource !== assessedResource) {
    return { status: "repreflight_required", reasons: [ConsistencyReason.RESOURCE_MISMATCH] };
  }

  const options = preflight.preflightContext.paymentOptions;
  if (options.length === 0) {
    return { status: "insufficient_context", reasons: [ConsistencyReason.NO_OBSERVED_PAYMENT_OPTIONS] };
  }

  if (options.some(option => optionMatches(option, challenge))) return { status: "match", reasons: [] };

  return { status: "repreflight_required", reasons: [ConsistencyReason.PAYMENT_REQUIREMENTS_MISMATCH] };
}
