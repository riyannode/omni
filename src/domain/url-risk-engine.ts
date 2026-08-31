import type { Evidence, Recommendation, RiskLevel, RiskSignal } from "./risk.ts";
import { extractUrlRiskFeatures, URL_RISK_POLICY_VERSION, type UrlRiskAssessment, type UrlRiskFeatures, type UrlRiskSnapshot } from "./url-risk.ts";

const severityWeight: Record<RiskLevel, number> = { unknown: 0, low: 35, medium: 60, high: 85, critical: 100 };

function level(score: number): RiskLevel {
  if (score >= 80) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

function recommendation(score: number): Recommendation {
  if (score >= 80) return "do_not_proceed";
  if (score >= 50) return "manual_review";
  if (score >= 25) return "proceed_with_caution";
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
  assess(snapshot: UrlRiskSnapshot): UrlRiskAssessment {
    return this.assessFeatures(snapshot, extractUrlRiskFeatures(snapshot));
  }

  assessFeatures(snapshot: UrlRiskSnapshot, features: UrlRiskFeatures): UrlRiskAssessment {
    const signals: RiskSignal[] = [];
    const threat = !snapshot.threatIntelChecked ? "unknown" : snapshot.threatFindings.length === 0 ? "low" : features.threatMatchSeverity;
    let threatScore = threat === "unknown" || snapshot.threatFindings.length === 0 ? 0 : severityWeight[threat];
    for (const finding of snapshot.threatFindings) signal(signals, "THREAT_INTELLIGENCE_MATCH", finding.severity, finding.source, { indicatorType: finding.indicatorType, threatType: finding.threatType, indicator: finding.indicator, ...(finding.reference ? { reference: finding.reference } : {}) });
    if (features.hasDisallowedAddress) {
      signal(signals, "DISALLOWED_NETWORK_ADDRESS", "critical", "DNS", {});
      threatScore = Math.max(threatScore, 100);
    }

    const transportScore = features.tlsInvalid ? 35 : features.httpsDowngradeBlocked ? 60 : 0;
    if (features.tlsInvalid) signal(signals, "TLS_CERTIFICATE_INVALID", "medium", "TLS", {});
    if (features.httpsDowngradeBlocked) signal(signals, "HTTPS_DOWNGRADE_BLOCKED", "high", "HTTP probe", {});

    let networkScore = 0;
    if (features.serverError) { networkScore += 15; signal(signals, "HTTP_SERVER_ERROR", "low", "HTTP probe", {}); }
    if (features.redirectCount > 2) { networkScore += 10; signal(signals, "MULTIPLE_REDIRECTS_OBSERVED", "low", "HTTP probe", { count: features.redirectCount }); }
    if (features.missingSecurityHeaderCount > 0) signal(signals, "SECURITY_HEADERS_MISSING", "low", "HTTP probe", { count: features.missingSecurityHeaderCount });
    networkScore = Math.max(networkScore, features.hasDisallowedAddress ? 100 : 0);
    const errorsScore = Math.min(20, features.sourceErrorCount * 5);
    let score = Math.min(100, Math.max(threatScore, transportScore, networkScore) + errorsScore);
    if (features.completedSources === 0) score = Math.max(score, 50);

    const threatLevel = !snapshot.threatIntelChecked ? "unknown" : snapshot.threatFindings.length === 0 ? "low" : level(threatScore);
    const domainLevel = snapshot.rdap === undefined || snapshot.rdap.status === "unavailable" ? "unknown" : "low";
    const transportLevel = snapshot.tls === undefined || snapshot.tls.status === "unavailable" ? "unknown" : level(transportScore);
    const networkLevel = snapshot.dns === undefined || snapshot.dns.addresses.length === 0 ? "unknown" : level(networkScore);
    return {
      subject: snapshot.subject,
      policyVersion: URL_RISK_POLICY_VERSION,
      recommendation: recommendation(score),
      riskScore: score,
      evidenceCoverage: Number((features.completedSources / features.expectedSources).toFixed(2)),
      dimensions: {
        knownVulnerabilities: "unknown",
        knownExploitation: "unknown",
        packageSupplyChain: "unknown",
        repositorySecurityPractices: "unknown",
        maliciousInfrastructure: threatLevel,
        serviceIdentity: domainLevel,
        paymentConfigurationRisk: "unknown",
        endpointOperationalRisk: networkLevel
      },
      urlDimensions: { threatReputation: threatLevel, domainIdentity: domainLevel, transportSecurity: transportLevel, networkBehavior: networkLevel },
      signals,
      evidence: snapshot.evidence,
      sourceErrors: snapshot.sourceErrors,
      assessedAt: new Date().toISOString(),
      freshness: freshness(snapshot.evidence)
    };
  }
}
