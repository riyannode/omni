import type { RiskLevel } from "./risk.ts";

export type UrlRiskPolicy = {
  version: "omni-url-risk-v1";
  severityWeights: Record<RiskLevel, number>;
  scoreLevelThresholds: { medium: number; high: number; critical: number };
  recommendationThresholds: { caution: number; manualReview: number; doNotProceed: number };
  transport: { tlsInvalid: number; httpsDowngrade: number };
  network: { serverError: number; multipleRedirects: number };
  sourceError: { perError: number; cap: number };
  score: { maximum: number; zeroCoverageFloor: number };
};

export const DEFAULT_URL_RISK_POLICY: Readonly<UrlRiskPolicy> = Object.freeze({
  version: "omni-url-risk-v1",
  severityWeights: { unknown: 0, low: 35, medium: 60, high: 85, critical: 100 },
  scoreLevelThresholds: { medium: 25, high: 50, critical: 80 },
  recommendationThresholds: { caution: 25, manualReview: 50, doNotProceed: 80 },
  transport: { tlsInvalid: 35, httpsDowngrade: 60 },
  network: { serverError: 15, multipleRedirects: 10 },
  sourceError: { perError: 5, cap: 20 },
  score: { maximum: 100, zeroCoverageFloor: 50 }
});
