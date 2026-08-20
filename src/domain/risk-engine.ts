import type { Recommendation, RiskAssessment, RiskLevel, RiskSignal, RiskSnapshot } from "./risk.ts";

const severityWeight: Record<RiskLevel, number> = { unknown: 30, low: 10, medium: 35, high: 60, critical: 85 };
const severityRank: Record<RiskLevel, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };

function scoreLevel(score: number): RiskLevel {
  if (score >= 80) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}
function worstSeverity(levels: RiskLevel[]): RiskLevel {
  return levels.reduce<RiskLevel>((worst, current) => severityRank[current] > severityRank[worst] ? current : worst, "low");
}
function recommendation(score: number): Recommendation {
  if (score >= 80) return "do_not_proceed";
  if (score >= 50) return "manual_review";
  if (score >= 25) return "proceed_with_caution";
  return "proceed";
}
function push(signals: RiskSignal[], code: string, severity: Exclude<RiskLevel, "unknown">, source: string, detail: Record<string, unknown>) {
  signals.push({ code, severity, source, detail });
}

function evidenceCoverage(snapshot: RiskSnapshot): number {
  switch (snapshot.subject.type) {
    case "package": {
      const checks = [snapshot.vulnerabilities !== undefined, snapshot.exploitationChecked === true];
      if (snapshot.packageSupplyChain) checks.push(true);
      if (snapshot.threatIntelChecked !== undefined) checks.push(snapshot.threatIntelChecked);
      return checks.filter(Boolean).length / checks.length;
    }
    case "repository": return snapshot.scorecard === undefined ? 0 : 1;
    case "x402_endpoint": {
      const checks = [
        snapshot.endpoint?.listedOnCircle !== undefined,
        snapshot.activeProbeChecked === true,
        snapshot.historyChecked === true,
        snapshot.threatIntelChecked === true
      ];
      return checks.filter(Boolean).length / checks.length;
    }
    case "dependency_set": return snapshot.evidence.length === 0 ? 0 : 1;
  }
}

export class RiskEngine {
  assess(snapshot: RiskSnapshot): RiskAssessment {
    const signals: RiskSignal[] = [];
    const vulnerabilities = snapshot.vulnerabilities;
    const maxVulnScore = vulnerabilities?.reduce((max, vuln) => Math.max(max, severityWeight[vuln.severity]), 0) ?? 0;
    const exploitedScore = vulnerabilities?.some(v => v.knownExploited) ? 90 : 0;
    for (const vuln of vulnerabilities ?? []) {
      if (vuln.severity === "critical" || vuln.severity === "high") push(signals, "KNOWN_VULNERABILITY", vuln.severity, "OSV", { id: vuln.id });
      if (vuln.knownExploited) push(signals, "KNOWN_EXPLOITED_VULNERABILITY", "critical", "CISA KEV", { id: vuln.id });
    }

    let packageRisk: number | undefined;
    if (snapshot.packageSupplyChain) {
      packageRisk = 0;
      if (snapshot.packageSupplyChain.deprecated) { packageRisk += 15; push(signals, "PACKAGE_DEPRECATED", "medium", "npm Registry", {}); }
      if (snapshot.packageSupplyChain.hasInstallScript) { packageRisk += 10; push(signals, "INSTALL_LIFECYCLE_SCRIPT_PRESENT", "low", "npm Registry", {}); }
      if (!snapshot.packageSupplyChain.integrityPresent) { packageRisk += 20; push(signals, "PACKAGE_INTEGRITY_MISSING", "medium", "npm Registry", {}); }
      if (snapshot.packageSupplyChain.maintainerCount === 0) { packageRisk += 10; push(signals, "NO_MAINTAINER_METADATA", "low", "npm Registry", {}); }
    }

    let repoRisk: number | undefined;
    if (snapshot.scorecard !== undefined) repoRisk = Math.round((10 - Math.max(0, Math.min(10, snapshot.scorecard))) * 6);

    let maliciousInfrastructureRisk: number | undefined;
    if (snapshot.threatIntelChecked) {
      maliciousInfrastructureRisk = 0;
      for (const finding of snapshot.threatFindings ?? []) {
        const weight = finding.severity === "critical" ? 100 : finding.severity === "high" ? 85 : finding.severity === "medium" ? 60 : 35;
        maliciousInfrastructureRisk = Math.max(maliciousInfrastructureRisk, weight);
        push(signals, "THREAT_INTELLIGENCE_MATCH", finding.severity, finding.source, {
          indicatorType: finding.indicatorType, threatType: finding.threatType, ...(finding.reference ? { reference: finding.reference } : {})
        });
      }
    }

    let identityRisk: number | undefined;
    let endpointRisk: number | undefined;
    if (snapshot.endpoint) {
      identityRisk = snapshot.endpoint.listedOnCircle === true ? 0 : snapshot.endpoint.listedOnCircle === false ? 25 : undefined;
      if (snapshot.endpoint.listedOnCircle === false) push(signals, "NOT_LISTED_IN_CIRCLE_DISCOVERY", "medium", "Circle Discovery", {});
      endpointRisk = 0;
      if (snapshot.endpoint.responseStatus !== undefined && snapshot.endpoint.responseStatus >= 500) { endpointRisk += 25; push(signals, "ENDPOINT_SERVER_ERROR", "medium", "OMNI active probe", { status: snapshot.endpoint.responseStatus }); }
      if (snapshot.endpoint.responseStatus !== undefined && snapshot.endpoint.responseStatus !== 402) { endpointRisk += 10; push(signals, "X402_HANDSHAKE_NOT_OBSERVED", "low", "OMNI active probe", { status: snapshot.endpoint.responseStatus }); }
      if (snapshot.endpoint.supportsGateway === false && snapshot.endpoint.supportsVanilla === false) { endpointRisk += 30; push(signals, "NO_SUPPORTED_X402_PATH", "medium", "Circle Discovery", {}); }
    }

    let paymentRisk: number | undefined;
    if (snapshot.historyChecked && snapshot.endpointHistory) {
      const h = snapshot.endpointHistory;
      paymentRisk = 0;
      if (h.payToChangeCount > 0) { paymentRisk += 35; push(signals, "PAYMENT_DESTINATION_CHANGED", "high", "OMNI history", { changeCount: h.payToChangeCount }); }
      if (h.networkChangeCount > 0) { paymentRisk += 20; push(signals, "PAYMENT_NETWORK_CHANGED", "medium", "OMNI history", { changeCount: h.networkChangeCount }); }
      if (h.priceChangeCount > 0) { paymentRisk += 10; push(signals, "PRICE_CONFIGURATION_CHANGED", "low", "OMNI history", { changeCount: h.priceChangeCount }); }
      if (h.schemaChangeCount > 0) { paymentRisk += 10; push(signals, "SERVICE_SCHEMA_CHANGED", "low", "OMNI history", { changeCount: h.schemaChangeCount }); }
      if (h.providerChangeCount > 0) { paymentRisk += 20; push(signals, "PROVIDER_IDENTITY_CHANGED", "medium", "OMNI history", { changeCount: h.providerChangeCount }); }
    }

    const coverage = evidenceCoverage(snapshot);
    const sourcePenalty = Math.min(20, (snapshot.sourceErrors?.length ?? 0) * 5);
    let score = Math.min(100, Math.max(maxVulnScore, exploitedScore, packageRisk ?? 0, repoRisk ?? 0, maliciousInfrastructureRisk ?? 0, identityRisk ?? 0, paymentRisk ?? 0, endpointRisk ?? 0) + sourcePenalty);
    if (coverage === 0) score = Math.max(score, 50);
    else if (coverage < 1 && (snapshot.sourceErrors?.length ?? 0) > 0) score = Math.max(score, 25);

    const knownVulnerabilities: RiskLevel = vulnerabilities === undefined ? "unknown" : vulnerabilities.length === 0 ? "low" : worstSeverity(vulnerabilities.map(v => v.severity));
    const knownExploitation: RiskLevel = vulnerabilities === undefined ? "unknown" : vulnerabilities.length === 0 ? "low" : snapshot.exploitationChecked ? scoreLevel(exploitedScore) : "unknown";

    return {
      subject: snapshot.subject,
      recommendation: recommendation(score),
      riskScore: score,
      evidenceCoverage: Number(coverage.toFixed(2)),
      dimensions: {
        knownVulnerabilities,
        knownExploitation,
        packageSupplyChain: packageRisk === undefined ? "unknown" : scoreLevel(packageRisk),
        repositorySecurityPractices: repoRisk === undefined ? "unknown" : scoreLevel(repoRisk),
        maliciousInfrastructure: maliciousInfrastructureRisk === undefined ? "unknown" : scoreLevel(maliciousInfrastructureRisk),
        serviceIdentity: identityRisk === undefined ? "unknown" : scoreLevel(identityRisk),
        paymentConfigurationRisk: paymentRisk === undefined ? "unknown" : scoreLevel(paymentRisk),
        endpointOperationalRisk: endpointRisk === undefined ? "unknown" : scoreLevel(endpointRisk)
      },
      signals,
      evidence: snapshot.evidence,
      sourceErrors: snapshot.sourceErrors ?? [],
      assessedAt: new Date().toISOString()
    };
  }
}
