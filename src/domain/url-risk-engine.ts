import type { Evidence, Recommendation, RiskLevel, RiskSignal } from "./risk.ts";
import { DEFAULT_URL_RISK_POLICY, type UrlRiskPolicy } from "./url-risk-policy.ts";
import { extractUrlRiskFeatures, type UrlRiskAssessment, type UrlRiskFeatures, type UrlRiskSnapshot } from "./url-risk.ts";

function level(score: number, policy: UrlRiskPolicy): RiskLevel {
  if (score >= policy.scoreLevelThresholds.critical) return "critical";
  if (score >= policy.scoreLevelThresholds.high) return "high";
  if (score >= policy.scoreLevelThresholds.medium) return "medium";
  return "low";
}
function recommendation(score: number, policy: UrlRiskPolicy): Recommendation {
  if (score >= policy.recommendationThresholds.doNotProceed) return "do_not_proceed";
  if (score >= policy.recommendationThresholds.manualReview) return "manual_review";
  if (score >= policy.recommendationThresholds.caution) return "proceed_with_caution";
  return "proceed";
}
function signal(signals: RiskSignal[], code: string, severity: Exclude<RiskLevel, "unknown">, source: string, detail: Record<string, unknown> = {}): void {
  signals.push({ code, severity, source, detail });
}
function freshness(evidence: Evidence[]): UrlRiskAssessment["freshness"] {
  const observed = evidence.map(item => item.observedAt).sort();
  const expires = evidence.flatMap(item => item.expiresAt ? [item.expiresAt] : []).sort();
  return { oldestEvidenceAt: observed[0] ?? null, newestEvidenceAt: observed.at(-1) ?? null, ...(expires[0] ? { expiresAt: expires[0] } : {}) };
}

export class UrlRiskEngine {
  constructor(private readonly policy: UrlRiskPolicy = DEFAULT_URL_RISK_POLICY) {}

  assess(snapshot: UrlRiskSnapshot): UrlRiskAssessment {
    return this.assessFeatures(snapshot, extractUrlRiskFeatures(snapshot));
  }

  assessFeatures(snapshot: UrlRiskSnapshot, features: UrlRiskFeatures): UrlRiskAssessment {
    const policy = this.policy;
    const signals: RiskSignal[] = [];
    const threat = !snapshot.threatIntelChecked ? "unknown" : snapshot.threatFindings.length === 0 ? "low" : features.threatMatchSeverity;
    let threatScore = threat === "unknown" || snapshot.threatFindings.length === 0 ? 0 : policy.severityWeights[threat];
    for (const finding of snapshot.threatFindings) signal(signals, "THREAT_INTELLIGENCE_MATCH", finding.severity, finding.source, { indicatorType: finding.indicatorType, threatType: finding.threatType, indicator: finding.indicator, ...(finding.reference ? { reference: finding.reference } : {}) });
    if (features.hasDisallowedAddress) {
      signal(signals, "DISALLOWED_NETWORK_ADDRESS", "critical", "DNS", {});
      threatScore = Math.max(threatScore, policy.score.maximum);
    }

    const transportScore = Math.max(features.tlsInvalid ? policy.transport.tlsInvalid : 0, features.httpsDowngradeBlocked ? policy.transport.httpsDowngrade : 0);
    if (features.tlsInvalid) signal(signals, "TLS_CERTIFICATE_INVALID", "medium", "TLS", {});
    if (features.httpsDowngradeBlocked) signal(signals, "HTTPS_DOWNGRADE_BLOCKED", "high", "HTTP probe", {});

    let networkScore = 0;
    if (features.serverError) { networkScore += policy.network.serverError; signal(signals, "HTTP_SERVER_ERROR", "low", "HTTP probe", {}); }
    if (features.redirectCount > 2) { networkScore += policy.network.multipleRedirects; signal(signals, "MULTIPLE_REDIRECTS_OBSERVED", "low", "HTTP probe", { count: features.redirectCount }); }
    if (features.missingSecurityHeaderCount > 0) signal(signals, "SECURITY_HEADERS_MISSING", "low", "HTTP probe", { count: features.missingSecurityHeaderCount });
    networkScore = Math.max(networkScore, features.hasDisallowedAddress ? policy.score.maximum : 0);
    const errorsScore = Math.min(policy.sourceError.cap, features.sourceErrorCount * policy.sourceError.perError);
    let score = Math.min(policy.score.maximum, Math.max(threatScore, transportScore, networkScore) + errorsScore);
    if (features.completedSources === 0) score = Math.max(score, policy.score.zeroCoverageFloor);

    const threatLevel = !snapshot.threatIntelChecked ? "unknown" : snapshot.threatFindings.length === 0 ? "low" : level(threatScore, policy);
    const domainLevel = snapshot.rdap?.status === "registered" ? "low" : "unknown";
    const transportLevel = snapshot.tls === undefined || snapshot.tls.status === "unavailable" ? "unknown" : level(transportScore, policy);
    const networkLevel = snapshot.dns === undefined || snapshot.dns.addresses.length === 0 ? "unknown" : level(networkScore, policy);
    return {
      subject: snapshot.subject,
      policyVersion: policy.version,
      recommendation: recommendation(score, policy),
      riskScore: score,
      evidenceCoverage: Number((features.completedSources / features.expectedSources).toFixed(2)),
      dimensions: { knownVulnerabilities: "unknown", knownExploitation: "unknown", packageSupplyChain: "unknown", repositorySecurityPractices: "unknown", maliciousInfrastructure: threatLevel, serviceIdentity: domainLevel, paymentConfigurationRisk: "unknown", endpointOperationalRisk: networkLevel },
      urlDimensions: { threatReputation: threatLevel, domainIdentity: domainLevel, transportSecurity: transportLevel, networkBehavior: networkLevel },
      signals,
      evidence: snapshot.evidence,
      sourceErrors: snapshot.sourceErrors,
      assessedAt: new Date().toISOString(),
      freshness: freshness(snapshot.evidence)
    };
  }
}
