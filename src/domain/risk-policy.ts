import type { RiskLevel } from "./risk.ts";

export const RISK_POLICY_VERSION = "omni-risk-v1" as const;

export type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly unknown[]
    ? { readonly [K in keyof T]: DeepReadonly<T[K]> }
    : T extends object
      ? { readonly [K in keyof T]: DeepReadonly<T[K]> }
      : T;

type SeverityWeights = Record<RiskLevel, number>;
type SeverityRanks = Record<RiskLevel, number>;

export type RiskPolicy = {
  version: string;
  severityWeights: SeverityWeights;
  severityRanks: SeverityRanks;
  scoreLevelThresholds: { medium: number; high: number; critical: number };
  recommendationThresholds: { caution: number; manualReview: number; doNotProceed: number };
  score: { minimum: number; maximum: number; sourceErrorPenalty: number; sourceErrorPenaltyCap: number; zeroCoverageFloor: number; partialCoverageFloor: number };
  package: { deprecated: number; installScript: number; missingIntegrity: number; noMaintainer: number; knownExploitation: number };
  repository: { scorecardMaximum: number; scorecardRiskMultiplier: number };
  threatIntel: Record<Exclude<RiskLevel, "unknown">, number>;
  endpoint: { unlisted: number; serverError: number; handshakeMissing: number; noSupportedPath: number };
  payment: { payToChange: number; networkChange: number; priceChange: number; schemaChange: number; providerChange: number };
};

export type ReadonlyRiskPolicy = DeepReadonly<RiskPolicy>;

export function deepFreeze<T>(value: T): DeepReadonly<T> {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
  }
  return value as DeepReadonly<T>;
}

export const DEFAULT_RISK_POLICY: ReadonlyRiskPolicy = deepFreeze({
  version: RISK_POLICY_VERSION,
  severityWeights: { unknown: 30, low: 10, medium: 35, high: 60, critical: 85 },
  severityRanks: { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 },
  scoreLevelThresholds: { medium: 25, high: 50, critical: 80 },
  recommendationThresholds: { caution: 25, manualReview: 50, doNotProceed: 80 },
  score: { minimum: 0, maximum: 100, sourceErrorPenalty: 5, sourceErrorPenaltyCap: 20, zeroCoverageFloor: 50, partialCoverageFloor: 25 },
  package: { deprecated: 15, installScript: 10, missingIntegrity: 20, noMaintainer: 10, knownExploitation: 90 },
  repository: { scorecardMaximum: 10, scorecardRiskMultiplier: 6 },
  threatIntel: { low: 35, medium: 60, high: 85, critical: 100 },
  endpoint: { unlisted: 25, serverError: 25, handshakeMissing: 10, noSupportedPath: 30 },
  payment: { payToChange: 35, networkChange: 20, priceChange: 10, schemaChange: 10, providerChange: 20 }
});
