import type { Recommendation, RiskAssessment, RiskLevel, RiskSignal, RiskSnapshot } from "./risk.ts";
import { extractRiskFeatures, type RiskFeatures } from "./risk-features.ts";
import { DEFAULT_RISK_POLICY, type RiskPolicy } from "./risk-policy.ts";

function scoreLevel(score: number, policy: RiskPolicy): RiskLevel {
  if (score >= policy.scoreLevelThresholds.critical) return "critical";
  if (score >= policy.scoreLevelThresholds.high) return "high";
  if (score >= policy.scoreLevelThresholds.medium) return "medium";
  return "low";
}
function worstSeverity(levels: RiskLevel[], policy: RiskPolicy): RiskLevel {
  return levels.reduce<RiskLevel>((worst, current) => policy.severityRanks[current] > policy.severityRanks[worst] ? current : worst, "low");
}
function recommendation(score: number, policy: RiskPolicy): Recommendation {
  if (score >= policy.recommendationThresholds.doNotProceed) return "do_not_proceed";
  if (score >= policy.recommendationThresholds.manualReview) return "manual_review";
  if (score >= policy.recommendationThresholds.caution) return "proceed_with_caution";
  return "proceed";
}
function push(signals: RiskSignal[], code: string, severity: Exclude<RiskLevel, "unknown">, source: string, detail: Record<string, unknown>) {
  signals.push({ code, severity, source, detail });
}

export class RiskEngine {
  constructor(private readonly policy: RiskPolicy = DEFAULT_RISK_POLICY) {}

  assess(snapshot: RiskSnapshot): RiskAssessment { return this.assessFeatures(snapshot, extractRiskFeatures(snapshot)); }

  assessFeatures(snapshot: RiskSnapshot, features: RiskFeatures): RiskAssessment {
    const policy = this.policy;
    const signals: RiskSignal[] = [];
    const maxVulnScore = features.vulnerabilities?.reduce((max, vuln) => Math.max(max, policy.severityWeights[vuln.severity]), 0) ?? 0;
    const exploitedScore = features.knownExploitedVulnerabilityCount > 0 ? policy.package.knownExploitation : 0;
    for (const vuln of features.vulnerabilities ?? []) {
      if (vuln.severity === "critical" || vuln.severity === "high") push(signals, "KNOWN_VULNERABILITY", vuln.severity, "OSV", { id: vuln.id });
      if (vuln.knownExploited) push(signals, "KNOWN_EXPLOITED_VULNERABILITY", "critical", "CISA KEV", { id: vuln.id });
    }

    let packageRisk: number | undefined;
    if (features.package.present) {
      packageRisk = 0;
      if (features.package.deprecated) { packageRisk += policy.package.deprecated; push(signals, "PACKAGE_DEPRECATED", "medium", "npm Registry", {}); }
      if (features.package.installLifecycleScript) { packageRisk += policy.package.installScript; push(signals, "INSTALL_LIFECYCLE_SCRIPT_PRESENT", "low", "npm Registry", {}); }
      if (!features.package.integrityPresent) { packageRisk += policy.package.missingIntegrity; push(signals, "PACKAGE_INTEGRITY_MISSING", "medium", "npm Registry", {}); }
      if (features.package.maintainerCount === 0) { packageRisk += policy.package.noMaintainer; push(signals, "NO_MAINTAINER_METADATA", "low", "npm Registry", {}); }
    }

    let repoRisk: number | undefined;
    if (features.scorecard !== undefined) repoRisk = Math.round((policy.repository.scorecardMaximum - Math.max(0, Math.min(policy.repository.scorecardMaximum, features.scorecard))) * policy.repository.scorecardRiskMultiplier);

    let maliciousInfrastructureRisk: number | undefined;
    if (features.threatIntel.checked) {
      maliciousInfrastructureRisk = 0;
      for (const finding of features.threatIntel.findings) {
        const weight = policy.threatIntel[finding.severity];
        maliciousInfrastructureRisk = Math.max(maliciousInfrastructureRisk, weight);
        push(signals, "THREAT_INTELLIGENCE_MATCH", finding.severity, finding.source, { indicatorType: finding.indicatorType, threatType: finding.threatType, ...(finding.reference ? { reference: finding.reference } : {}) });
      }
    }

    let identityRisk: number | undefined;
    let endpointRisk: number | undefined;
    if (features.endpoint.present) {
      identityRisk = features.endpoint.listedOnCircle === true ? 0 : features.endpoint.listedOnCircle === false ? policy.endpoint.unlisted : undefined;
      if (features.endpoint.listedOnCircle === false) push(signals, "NOT_LISTED_IN_CIRCLE_DISCOVERY", "medium", "Circle Discovery", {});
      endpointRisk = 0;
      if (features.endpoint.responseStatus !== undefined && features.endpoint.responseStatus >= 500) { endpointRisk += policy.endpoint.serverError; push(signals, "ENDPOINT_SERVER_ERROR", "medium", "OMNI active probe", { status: features.endpoint.responseStatus }); }
      if (features.endpoint.responseStatus !== undefined && features.endpoint.responseStatus !== 402) { endpointRisk += policy.endpoint.handshakeMissing; push(signals, "X402_HANDSHAKE_NOT_OBSERVED", "low", "OMNI active probe", { status: features.endpoint.responseStatus }); }
      if (features.endpoint.supportsGateway === false && features.endpoint.supportsVanilla === false) { endpointRisk += policy.endpoint.noSupportedPath; push(signals, "NO_SUPPORTED_X402_PATH", "medium", "Circle Discovery", {}); }
    }

    let paymentRisk: number | undefined;
    if (features.history.checked) {
      paymentRisk = 0;
      if (features.history.payToChangeCount > 0) { paymentRisk += policy.payment.payToChange; push(signals, "PAYMENT_DESTINATION_CHANGED", "high", "OMNI history", { changeCount: features.history.payToChangeCount }); }
      if (features.history.networkChangeCount > 0) { paymentRisk += policy.payment.networkChange; push(signals, "PAYMENT_NETWORK_CHANGED", "medium", "OMNI history", { changeCount: features.history.networkChangeCount }); }
      if (features.history.priceChangeCount > 0) { paymentRisk += policy.payment.priceChange; push(signals, "PRICE_CONFIGURATION_CHANGED", "low", "OMNI history", { changeCount: features.history.priceChangeCount }); }
      if (features.history.schemaChangeCount > 0) { paymentRisk += policy.payment.schemaChange; push(signals, "SERVICE_SCHEMA_CHANGED", "low", "OMNI history", { changeCount: features.history.schemaChangeCount }); }
      if (features.history.providerChangeCount > 0) { paymentRisk += policy.payment.providerChange; push(signals, "PROVIDER_IDENTITY_CHANGED", "medium", "OMNI history", { changeCount: features.history.providerChangeCount }); }
    }

    const coverage = features.coverage.expected === 0 ? 0 : features.coverage.completed / features.coverage.expected;
    const sourcePenalty = Math.min(policy.score.sourceErrorPenaltyCap, features.sourceErrorCount * policy.score.sourceErrorPenalty);
    let score = Math.min(policy.score.maximum, Math.max(policy.score.minimum, Math.max(maxVulnScore, exploitedScore, packageRisk ?? 0, repoRisk ?? 0, maliciousInfrastructureRisk ?? 0, identityRisk ?? 0, paymentRisk ?? 0, endpointRisk ?? 0) + sourcePenalty));
    if (coverage === 0) score = Math.max(score, policy.score.zeroCoverageFloor);
    else if (coverage < 1 && features.sourceErrorCount > 0) score = Math.max(score, policy.score.partialCoverageFloor);

    const knownVulnerabilities: RiskLevel = features.vulnerabilities === undefined ? "unknown" : features.vulnerabilities.length === 0 ? "low" : worstSeverity(features.vulnerabilities.map(v => v.severity), policy);
    const knownExploitation: RiskLevel = features.vulnerabilities === undefined ? "unknown" : features.vulnerabilities.length === 0 ? "low" : features.exploitationChecked ? scoreLevel(exploitedScore, policy) : "unknown";
    return {
      subject: snapshot.subject,
      policyVersion: policy.version,
      recommendation: recommendation(score, policy),
      riskScore: score,
      evidenceCoverage: Number(coverage.toFixed(2)),
      dimensions: {
        knownVulnerabilities, knownExploitation,
        packageSupplyChain: packageRisk === undefined ? "unknown" : scoreLevel(packageRisk, policy),
        repositorySecurityPractices: repoRisk === undefined ? "unknown" : scoreLevel(repoRisk, policy),
        maliciousInfrastructure: maliciousInfrastructureRisk === undefined ? "unknown" : scoreLevel(maliciousInfrastructureRisk, policy),
        serviceIdentity: identityRisk === undefined ? "unknown" : scoreLevel(identityRisk, policy),
        paymentConfigurationRisk: paymentRisk === undefined ? "unknown" : scoreLevel(paymentRisk, policy),
        endpointOperationalRisk: endpointRisk === undefined ? "unknown" : scoreLevel(endpointRisk, policy)
      },
      signals, evidence: snapshot.evidence, sourceErrors: snapshot.sourceErrors ?? [], assessedAt: new Date().toISOString()
    };
  }
}
