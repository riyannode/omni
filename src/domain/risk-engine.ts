import type { Recommendation, RepositoryDependencyVulnerabilityFinding, RepositoryThreatIntelFinding, RepositoryRiskSummary, RiskAssessment, RiskLevel, RiskDimensionLevel, RiskSignal, RiskSnapshot, ScoreStatus } from "./risk.ts";
import { AGENT_POLICY_VERSION } from "./risk.ts";
import { extractRiskFeatures, type RiskFeatures } from "./risk-features.ts";
import { DEFAULT_RISK_POLICY, type ReadonlyRiskPolicy } from "./risk-policy.ts";

function scoreLevel(score: number, policy: ReadonlyRiskPolicy): RiskLevel {
  if (score >= policy.scoreLevelThresholds.critical) return "critical";
  if (score >= policy.scoreLevelThresholds.high) return "high";
  if (score >= policy.scoreLevelThresholds.medium) return "medium";
  return "low";
}

function worstSeverity(levels: RiskLevel[], policy: ReadonlyRiskPolicy): RiskLevel {
  return levels.filter(level => level !== "unknown").reduce<RiskLevel | undefined>((worst, current) => worst === undefined || policy.severityRanks[current] > policy.severityRanks[worst] ? current : worst, undefined) ?? "unknown";
}

function recommendation(score: number, policy: ReadonlyRiskPolicy, status: ScoreStatus, subjectType: RiskSnapshot["subject"]["type"]): Recommendation {
  if (score >= policy.recommendationThresholds.doNotProceed) return "do_not_proceed";
  if ((subjectType === "repository" || subjectType === "agent") && status !== "measured") return "manual_review";
  if (score >= policy.recommendationThresholds.manualReview) return "manual_review";
  if (score >= policy.recommendationThresholds.caution) return "proceed_with_caution";
  return "proceed";
}

function push(signals: RiskSignal[], code: string, severity: Exclude<RiskLevel, "unknown">, source: string, detail: Record<string, unknown>) {
  signals.push({ code, severity, source, detail });
}

function freshness(evidence: RiskSnapshot["evidence"]): RiskAssessment["freshness"] {
  const observedAt = evidence.map(item => item.observedAt).sort();
  const deadlines = evidence.flatMap(item => item.expiresAt ? [item.expiresAt] : []).sort();
  return { oldestEvidenceAt: observedAt[0] ?? null, newestEvidenceAt: observedAt.at(-1) ?? null, ...(deadlines[0] ? { expiresAt: deadlines[0] } : {}) };
}

function highestSeverity(counts: Record<RiskLevel, number>, policy: ReadonlyRiskPolicy): RiskLevel | null {
  const known = (Object.keys(counts) as RiskLevel[]).filter(level => level !== "unknown" && counts[level] > 0);
  if (known.length > 0) return known.sort((left, right) => policy.severityRanks[right] - policy.severityRanks[left])[0] ?? null;
  return counts.unknown > 0 ? "unknown" : null;
}

function repositoryRiskSummary(snapshot: RiskSnapshot, features: RiskFeatures, policy: ReadonlyRiskPolicy): RepositoryRiskSummary | undefined {
  const repositoryEvidence = snapshot.repositoryEvidence;
  if (!repositoryEvidence) return undefined;

  const vulnerabilitySummaryTrusted = validSummaryStatus(features.repository.dependencyVulnerabilitySummaryStatus) && features.repository.dependencyVulnerabilitySummaryValid;
  const vulnerabilityCounts = { ...features.repository.dependencyVulnerabilityCountsBySeverity };
  if (!vulnerabilitySummaryTrusted) {
    for (const level of Object.keys(vulnerabilityCounts) as RiskLevel[]) vulnerabilityCounts[level] = 0;
    for (const finding of features.repository.retainedDependencyVulnerabilities) vulnerabilityCounts[finding.vulnerability.severity] += 1;
  }
  // VALID and TRUNCATED summaries retain authoritative aggregate counts; only invalid or missing summaries fall back to retained detail.
  const vulnerabilityTotal = Object.values(vulnerabilityCounts).reduce((total, count) => total + count, 0);
  const maliciousObserved = vulnerabilitySummaryTrusted
    ? features.repository.maliciousPackageObservationCount
    : features.repository.retainedMaliciousPackageObservations.length;

  const threatSummaryTrusted = validSummaryStatus(features.repository.dependencyThreatIntelSummaryStatus) && features.repository.dependencyThreatIntelSummaryValid;
  const threatCounts = { ...features.repository.dependencyThreatIntelCountsBySeverity };
  if (!threatSummaryTrusted) {
    for (const level of Object.keys(threatCounts) as Array<Exclude<RiskLevel, "unknown">>) threatCounts[level] = 0;
    for (const finding of features.repository.retainedDependencyThreatIntelFindings) threatCounts[finding.finding.severity] += 1;
  }
  // As above, preserve trusted aggregate counts even when detail retention was truncated.
  const threatTotal = Object.values(threatCounts).reduce((total, count) => total + count, 0);
  const resolution = repositoryEvidence.dependencyResolution;
  const resolutionComplete = resolution
    ? resolution.manifestDiscoveryComplete && resolution.unsupportedEcosystems.length === 0 && resolution.unresolvedDependencyCount === 0
    : repositoryEvidence.dependencies.unresolved.length === 0 && !features.repository.partial;

  return {
    dependencies: { exact: features.repository.exactDependencyCount, unresolved: features.repository.unresolvedDependencyCount, resolutionComplete },
    vulnerabilities: {
      total: vulnerabilityTotal,
      unknown: vulnerabilityCounts.unknown,
      low: vulnerabilityCounts.low,
      medium: vulnerabilityCounts.medium,
      high: vulnerabilityCounts.high,
      critical: vulnerabilityCounts.critical,
      highestSeverity: highestSeverity(vulnerabilityCounts, policy)
    },
    knownExploitation: { kevMatches: features.repository.cisaKevMatchedCount, status: repositoryEvidence.dependencyVulnerabilities.cisaKev.status },
    maliciousPackages: { observed: maliciousObserved },
    threatIntelligence: { status: repositoryEvidence.dependencyThreatIntel.status, findings: threatTotal, highestSeverity: highestSeverity({ unknown: 0, ...threatCounts }, policy) as Exclude<RiskLevel, "unknown"> | null },
    provenance: { sourceMismatch: features.repository.provenanceStates.VERIFIED_SOURCE_MISMATCH, commitMismatch: features.repository.provenanceStates.VERIFIED_COMMIT_MISMATCH, unavailable: features.repository.provenanceStates.UNAVAILABLE },
    securityPractices: { mutableActions: features.repository.mutableActionRefCount, workflowWritePermissions: features.repository.workflowWritePermissionCount, downloadExecuteFindings: features.repository.downloadExecutePatternCount }
  };
}

function scoreStatus(features: RiskFeatures): ScoreStatus {
  if (features.subject.type === "agent" && features.agent.identityStatus !== "REGISTERED") return "insufficient_evidence";
  if (features.coverage.expected === 0 || features.coverage.completed === 0) return "insufficient_evidence";
  if (features.subject.type === "repository" && features.repository.present && (
    (features.repository.dependencyVulnerabilityStatus !== undefined && features.repository.dependencyVulnerabilityStatus !== "NOT_CHECKED" && !features.repository.dependencyVulnerabilitySummaryValid)
    || (features.repository.dependencyThreatIntelStatus !== undefined && features.repository.dependencyThreatIntelStatus !== "NOT_CHECKED" && !features.repository.dependencyThreatIntelSummaryValid)
  )) return "measured_partial";
  return features.coverage.completed === features.coverage.expected ? "measured" : "measured_partial";
}

function validSummaryStatus(status: RiskFeatures["repository"]["dependencyVulnerabilitySummaryStatus"]): boolean {
  return status === "VALID" || status === "TRUNCATED";
}

function coordinateDetail(coordinate: { ecosystem: string; name: string; version: string }): Record<string, string> {
  return { ecosystem: coordinate.ecosystem, name: coordinate.name, version: coordinate.version };
}

function compareRepositoryVulnerabilities(left: RepositoryDependencyVulnerabilityFinding, right: RepositoryDependencyVulnerabilityFinding): number {
  const leftKey = `${left.coordinate.ecosystem}:${left.coordinate.name}@${left.coordinate.version}:${left.vulnerability.id}`;
  const rightKey = `${right.coordinate.ecosystem}:${right.coordinate.name}@${right.coordinate.version}:${right.vulnerability.id}`;
  return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
}

function compareRepositoryThreatIntel(left: RepositoryThreatIntelFinding, right: RepositoryThreatIntelFinding): number {
  const leftKey = JSON.stringify(left);
  const rightKey = JSON.stringify(right);
  return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
}

function maximumVulnerabilityRisk(features: RiskFeatures, policy: ReadonlyRiskPolicy): number {
  const repository = features.repository;
  if (repository.dependencyVulnerabilitySummaryValid) {
    return (Object.keys(repository.dependencyVulnerabilityCountsBySeverity) as RiskLevel[]).reduce((maximum, severity) => Math.max(maximum, repository.dependencyVulnerabilityCountsBySeverity[severity] > 0 ? policy.severityWeights[severity] : 0), 0);
  }
  return repository.retainedDependencyVulnerabilities.reduce((maximum, finding) => Math.max(maximum, policy.severityWeights[finding.vulnerability.severity]), 0);
}

function maximumThreatIntelRisk(features: RiskFeatures, policy: ReadonlyRiskPolicy): number {
  const repository = features.repository;
  if (repository.dependencyThreatIntelSummaryValid) {
    return (Object.keys(repository.dependencyThreatIntelCountsBySeverity) as Array<Exclude<RiskLevel, "unknown">>).reduce((maximum, severity) => Math.max(maximum, repository.dependencyThreatIntelCountsBySeverity[severity] > 0 ? policy.threatIntel[severity] : 0), 0);
  }
  return repository.retainedDependencyThreatIntelFindings.reduce((maximum, item) => Math.max(maximum, policy.threatIntel[item.finding.severity]), 0);
}

function highestObservedVulnerabilitySeverity(features: RiskFeatures, policy: ReadonlyRiskPolicy): RiskLevel {
  const repository = features.repository;
  if (repository.dependencyVulnerabilitySummaryValid) {
    const levels = (Object.keys(repository.dependencyVulnerabilityCountsBySeverity) as RiskLevel[]).filter(level => repository.dependencyVulnerabilityCountsBySeverity[level] > 0);
    return worstSeverity(levels, policy);
  }
  return worstSeverity(repository.retainedDependencyVulnerabilities.map(item => item.vulnerability.severity), policy);
}

/**
 * Agent-specific risk scoring following omni-agent-risk-v1.
 *
 * Observed signals feed dimensions via MAX aggregation:
 * - agentIdentity: registration status
 * - agentReputation: trusted-reviewer feedback (if policy exists)
 * - agentValidation: service/card evidence
 * - targetUrlRedirectsToPrivate: critical contradiction
 *
 * Registered=false => riskScore 0 + insufficient_evidence + manual_review.
 * RPC outage => sourceErrors + UNKNOWN coverage (not registered=false).
 * Real contradictions (e.g., target redirecting to private) must not end at riskScore 0.
 */
function assessAgentFeatures(snapshot: RiskSnapshot, features: RiskFeatures, policy: ReadonlyRiskPolicy): RiskAssessment {
  const signals: RiskSignal[] = [];
  const agent = features.agent;

  // --- agentIdentity dimension ---
  let agentIdentityRisk: RiskLevel = "unknown";
  let identityRiskScore = 0;
  if (agent.identityStatus === "REGISTERED") {
    agentIdentityRisk = "low";
    identityRiskScore = 0;
  } else if (agent.identityStatus === "NOT_REGISTERED") {
    // Confirmed nonexistent token
    agentIdentityRisk = "unknown"; // not_registered is not itself malicious
    identityRiskScore = 0;
  } else {
    // RPC/transport failure
    agentIdentityRisk = "unknown";
    identityRiskScore = 0;
  }

  // --- agentReputation dimension ---
  let reputationRiskScore = 0;
  if (agent.trustedFeedbackExists && agent.strongestTrustedRisk !== undefined) {
    reputationRiskScore = agent.strongestTrustedRisk;
    if (reputationRiskScore >= policy.scoreLevelThresholds.critical) {
      push(signals, "AGENT_REPUTATION_CRITICAL", "critical", "ERC-8004 ReputationRegistry", { score: reputationRiskScore });
    } else if (reputationRiskScore >= policy.scoreLevelThresholds.high) {
      push(signals, "AGENT_REPUTATION_HIGH", "high", "ERC-8004 ReputationRegistry", { score: reputationRiskScore });
    }
  }
  // No trusted feedback => reputationRiskScore stays 0 (unknown/insufficient)

  // --- agentValidation dimension ---
  let validationRiskScore = 0;
  if (agent.cardUnavailable) {
    // Card fetch failed — unknown, not malicious
    validationRiskScore = 0;
  } else if (agent.registrationMismatch) {
    // Mismatch between advertised and actual
    validationRiskScore = policy.endpoint.unlisted;
    push(signals, "AGENT_CARD_MISMATCH", "medium", "ERC-8004 Agent Card", {});
  } else if (snapshot.evidence.some(evidence => evidence.kind === "agent_card_inactive")) {
    // Structurally valid and self-referencing, but the registration is observed inactive.
    validationRiskScore = policy.endpoint.unlisted;
    push(signals, "AGENT_CARD_INACTIVE", "medium", "ERC-8004 Agent Card", { active: false });
  } else if (agent.servicesObserved) {
    validationRiskScore = 0;
  }

  // --- targetUrlRedirectsToPrivate dimension ---
  let targetUrlRiskScore = 0;
  if (agent.targetUrlRedirectsToPrivate) {
    targetUrlRiskScore = policy.score.maximum; // Critical contradiction
    push(signals, "AGENT_TARGET_REDIRECT_TO_PRIVATE", "critical", "OMNI active probe", { targetUrl: snapshot.evidence.find(e => e.kind === "agent_target_redirect_to_private")?.detail ?? {} });
  } else if (agent.targetUrlStatus === "NOT_ADVERTISED") {
    // Supplied URL was not advertised — deterministic contradiction.
    targetUrlRiskScore = policy.endpoint.unlisted;
    push(signals, "AGENT_TARGET_NOT_ADVERTISED", "medium", "OMNI active probe", {});
  }

  // --- MAX aggregation across independent dimensions ---
  const observedRisk = Math.max(
    identityRiskScore,
    reputationRiskScore,
    validationRiskScore,
    targetUrlRiskScore,
  );

  const coverage = features.coverage.expected === 0 ? 0 : features.coverage.completed / features.coverage.expected;
  const status = scoreStatus(features);
  const rawScore = Math.min(policy.score.maximum, Math.max(policy.score.minimum, observedRisk));
  let score = rawScore;

  // Agent floor: if registered but no real contradictions observed, score can be 0
  // Missing evidence affects coverage, not observed risk
  if (agent.identityStatus === "NOT_REGISTERED") {
    // Confirmed unregistered: score stays 0, force manual_review (never auto proceed/do_not_proceed)
    score = 0;
  }

  // Confirmed unregistered => manual_review (not proceed, not do_not_proceed)
  const finalRecommendation = (agent.identityStatus === "NOT_REGISTERED")
    ? "manual_review" as Recommendation
    : recommendation(score, policy, status, snapshot.subject.type);

  const knownVulnerabilities: RiskDimensionLevel = "not_applicable";
  const knownExploitation: RiskDimensionLevel = "not_applicable";

  return {
    subject: snapshot.subject,
    policyVersion: AGENT_POLICY_VERSION,
    scoreStatus: status,
    recommendation: finalRecommendation,
    riskScore: score,
    evidenceCoverage: Number(coverage.toFixed(2)),
    ...(features.coverage.modelVersion && features.coverage.sources ? { coverage: { modelVersion: features.coverage.modelVersion, resolvedWeight: features.coverage.completed, applicableWeight: features.coverage.expected, sources: features.coverage.sources } } : {}),
    dimensions: {
      knownVulnerabilities,
      knownExploitation,
      packageSupplyChain: "not_applicable" as const,
      repositorySecurityPractices: "not_applicable" as const,
      maliciousInfrastructure: "not_applicable" as const,
      serviceIdentity: "not_applicable" as const,
      paymentConfigurationRisk: "not_applicable" as const,
      endpointOperationalRisk: "not_applicable" as const,
    },
    signals,
    evidence: snapshot.evidence,
    sourceErrors: snapshot.sourceErrors ?? [],
    assessedAt: new Date().toISOString(),
    freshness: freshness(snapshot.evidence),
  };
}

export class RiskEngine {
  constructor(private readonly policy: ReadonlyRiskPolicy = DEFAULT_RISK_POLICY) {}

  assess(snapshot: RiskSnapshot): RiskAssessment { return this.assessFeatures(snapshot, extractRiskFeatures(snapshot)); }

  assessFeatures(snapshot: RiskSnapshot, features: RiskFeatures): RiskAssessment {
    const policy = this.policy;
    const signals: RiskSignal[] = [];
    const isRepository = snapshot.subject.type === "repository";
    const isAgent = snapshot.subject.type === "agent";
    const maxVulnScore = features.vulnerabilities?.reduce((max, vuln) => Math.max(max, policy.severityWeights[vuln.severity]), 0) ?? 0;
    const exploitedScore = features.knownExploitedVulnerabilityCount > 0 ? policy.package.knownExploitation : 0;
    for (const vuln of features.vulnerabilities ?? []) {
      if (vuln.severity === "critical" || vuln.severity === "high") push(signals, "KNOWN_VULNERABILITY", vuln.severity, "OSV", { id: vuln.id });
      if (vuln.knownExploited) push(signals, "KNOWN_EXPLOITED_VULNERABILITY", "critical", "CISA KEV", { id: vuln.id });
    }

    // Agent subjects use dedicated scoring
    if (isAgent) {
      return assessAgentFeatures(snapshot, features, policy);
    }

    let packageRisk: number | undefined;
    if (features.package.present) {
      packageRisk = 0;
      if (features.package.deprecated) { packageRisk += policy.package.deprecated; push(signals, "PACKAGE_DEPRECATED", "medium", "npm Registry", {}); }
      if (features.package.installLifecycleScript) { packageRisk += policy.package.installScript; push(signals, "INSTALL_LIFECYCLE_SCRIPT_PRESENT", "low", "npm Registry", {}); }
      if (!features.package.integrityPresent) { packageRisk += policy.package.missingIntegrity; push(signals, "PACKAGE_INTEGRITY_MISSING", "medium", "npm Registry", {}); }
      if (features.package.maintainerCount === 0) { packageRisk += policy.package.noMaintainer; push(signals, "NO_MAINTAINER_METADATA", "low", "npm Registry", {}); }
    }

    let repositorySecurityPracticeRisk: number | undefined;
    let repositoryVulnerabilityRisk: number | undefined;
    let repositoryKnownExploitationRisk: number | undefined;
    let repositoryMaliciousPackageRisk: number | undefined;
    let repositoryThreatIntelRisk: number | undefined;
    let repositoryKnownVulnerabilities: RiskLevel = "unknown";
    let repositoryKnownExploitation: RiskLevel = "unknown";
    let repositorySecurityPractices: RiskLevel = "unknown";
    let repositoryMaliciousInfrastructure: RiskLevel = "unknown";

    if (isRepository) {
      const practiceRisks: number[] = [];
      if (features.repository.partial) push(signals, "REPOSITORY_EVIDENCE_PARTIAL", "low", "GitHub repository evidence", {});
      if (features.scorecard !== undefined) {
        practiceRisks.push(Math.round((policy.repository.scorecardMaximum - Math.max(0, Math.min(policy.repository.scorecardMaximum, features.scorecard))) * policy.repository.scorecardRiskMultiplier));
      }
      if (features.repository.inspectedSecurityFileCount > 0) practiceRisks.push(0);
      if (features.repository.installLifecycleScriptCount > 0) { practiceRisks.push(policy.repository.installLifecycleScript); push(signals, "INSTALL_LIFECYCLE_SCRIPT_OBSERVED", "low", "GitHub repository evidence", { count: features.repository.installLifecycleScriptCount }); }
      if (features.repository.downloadExecutePatternCount > 0) { practiceRisks.push(policy.repository.downloadExecutePattern); push(signals, "DOWNLOAD_EXECUTE_PATTERN_OBSERVED", "high", "GitHub repository evidence", { count: features.repository.downloadExecutePatternCount }); }
      if (features.repository.mutableActionRefCount > 0) { practiceRisks.push(policy.repository.mutableGithubActionRef); push(signals, "MUTABLE_GITHUB_ACTION_REF_OBSERVED", "medium", "GitHub repository evidence", { count: features.repository.mutableActionRefCount }); }
      if (features.repository.workflowWritePermissionCount > 0) { practiceRisks.push(policy.repository.workflowWritePermission); push(signals, "WORKFLOW_WRITE_PERMISSION_OBSERVED", "medium", "GitHub repository evidence", { count: features.repository.workflowWritePermissionCount }); }
      if (features.repository.unresolvedDependencyCount > 0) push(signals, "DEPENDENCY_RESOLUTION_PARTIAL", "low", "GitHub repository evidence", { count: features.repository.unresolvedDependencyCount });
      if (features.repository.provenanceStates.VERIFIED_SOURCE_MISMATCH > 0) { practiceRisks.push(policy.repository.provenanceSourceMismatch); push(signals, "PROVENANCE_SOURCE_MISMATCH", "high", "deps.dev", { count: features.repository.provenanceStates.VERIFIED_SOURCE_MISMATCH }); }
      if (features.repository.provenanceStates.VERIFIED_COMMIT_MISMATCH > 0) { practiceRisks.push(policy.repository.provenanceCommitMismatch); push(signals, "PROVENANCE_COMMIT_MISMATCH", "high", "deps.dev", { count: features.repository.provenanceStates.VERIFIED_COMMIT_MISMATCH }); }
      if (practiceRisks.length > 0) repositorySecurityPracticeRisk = Math.max(...practiceRisks);

      repositoryVulnerabilityRisk = maximumVulnerabilityRisk(features, policy);
      const retainedVulnerabilities = [...features.repository.retainedDependencyVulnerabilities].sort(compareRepositoryVulnerabilities);
      for (const item of retainedVulnerabilities) {
        if (item.vulnerability.severity === "high" || item.vulnerability.severity === "critical") push(signals, "KNOWN_VULNERABILITY", item.vulnerability.severity, "OSV", { ...coordinateDetail(item.coordinate), id: item.vulnerability.id });
      }
      if (features.repository.dependencyVulnerabilitySummaryValid) {
        const retainedBySeverity = retainedVulnerabilities.reduce<Record<RiskLevel, number>>((counts, item) => { counts[item.vulnerability.severity] += 1; return counts; }, { unknown: 0, low: 0, medium: 0, high: 0, critical: 0 });
        const counts = features.repository.dependencyVulnerabilityCountsBySeverity;
        const omittedHigh = counts.high > retainedBySeverity.high;
        const omittedCritical = counts.critical > retainedBySeverity.critical;
        if (omittedHigh || omittedCritical) push(signals, "KNOWN_VULNERABILITY", omittedCritical ? "critical" : "high", "OSV", { observedCountsBySeverity: counts, retainedDetailCount: retainedVulnerabilities.length, summaryStatus: features.repository.dependencyVulnerabilitySummaryStatus });
      }
      const retainedKnownExploited = retainedVulnerabilities.filter(item => item.vulnerability.knownExploited);
      for (const item of retainedKnownExploited) push(signals, "KNOWN_EXPLOITED_VULNERABILITY", "critical", "CISA KEV", { ...coordinateDetail(item.coordinate), id: item.vulnerability.id });
      const knownExploitedObserved = features.repository.dependencyVulnerabilitySummaryValid ? features.repository.knownExploitedDependencyVulnerabilityCount : 0;
      if (knownExploitedObserved > 0 || features.repository.cisaKevMatchedCount > 0 || retainedKnownExploited.length > 0) {
        repositoryKnownExploitationRisk = policy.repository.knownExploitation;
        if (knownExploitedObserved > retainedKnownExploited.length || features.repository.cisaKevMatchedCount > retainedKnownExploited.length) push(signals, "KNOWN_EXPLOITED_VULNERABILITY", "critical", "CISA KEV", { observedCount: Math.max(knownExploitedObserved, features.repository.cisaKevMatchedCount), retainedDetailCount: retainedKnownExploited.length });
      }
      const maliciousObserved = features.repository.dependencyVulnerabilitySummaryValid ? features.repository.maliciousPackageObservationCount : 0;
      const retainedMalicious = [...features.repository.retainedMaliciousPackageObservations].sort((left, right) => `${left.coordinate.ecosystem}:${left.coordinate.name}@${left.coordinate.version}:${left.id}`.localeCompare(`${right.coordinate.ecosystem}:${right.coordinate.name}@${right.coordinate.version}:${right.id}`));
      if (maliciousObserved > 0 || retainedMalicious.length > 0) {
        repositoryMaliciousPackageRisk = policy.repository.maliciousPackageObservation;
        for (const item of retainedMalicious) push(signals, "MALICIOUS_PACKAGE_OBSERVED", "critical", "OSV", { ...coordinateDetail(item.coordinate), id: item.id });
        if (maliciousObserved > retainedMalicious.length) push(signals, "MALICIOUS_PACKAGE_OBSERVED", "critical", "OSV", { observedCount: maliciousObserved, retainedDetailCount: retainedMalicious.length });
      }

      repositoryVulnerabilityRisk = Math.max(repositoryVulnerabilityRisk, 0);
      repositoryKnownVulnerabilities = highestObservedVulnerabilitySeverity(features, policy);
      const vulnerabilityStatus = features.repository.dependencyVulnerabilityStatus;
      const summaryUsable = features.repository.dependencyVulnerabilitySummaryValid;
      const retainedKnownSeverity = retainedVulnerabilities.some(item => item.vulnerability.severity !== "unknown");
      if (!summaryUsable && !retainedKnownSeverity) repositoryKnownVulnerabilities = "unknown";
      if (repositoryKnownVulnerabilities === "unknown" && vulnerabilityStatus === "CHECKED" && summaryUsable && features.repository.dependencyVulnerabilityCountsBySeverity.unknown === 0) repositoryKnownVulnerabilities = "low";
      if (repositoryKnownVulnerabilities === "unknown" && vulnerabilityStatus === "NOT_CHECKED" && features.repository.exactDependencyCount === 0 && features.repository.unresolvedDependencyCount === 0 && features.repository.cisaKevStatus === "NOT_QUERIED") repositoryKnownVulnerabilities = "low";
      const cisaComplete = vulnerabilityStatus === "CHECKED" && (features.repository.cisaKevStatus === "CHECKED" || features.repository.cisaKevStatus === "NOT_QUERIED");
      if (repositoryKnownExploitationRisk !== undefined) repositoryKnownExploitation = "critical";
      else if (cisaComplete && summaryUsable) repositoryKnownExploitation = "low";
      else if (vulnerabilityStatus === "NOT_CHECKED" && features.repository.exactDependencyCount === 0 && features.repository.unresolvedDependencyCount === 0 && features.repository.cisaKevStatus === "NOT_QUERIED") repositoryKnownExploitation = "low";
      else repositoryKnownExploitation = "unknown";

      repositoryThreatIntelRisk = maximumThreatIntelRisk(features, policy);
      const retainedThreatFindings = [...features.repository.retainedDependencyThreatIntelFindings].sort(compareRepositoryThreatIntel);
      for (const item of retainedThreatFindings) push(signals, "THREAT_INTELLIGENCE_MATCH", item.finding.severity, item.finding.source, { ...coordinateDetail(item.coordinate), indicatorType: item.finding.indicatorType, threatType: item.finding.threatType, ...(item.finding.reference ? { reference: item.finding.reference } : {}) });
      if (features.repository.dependencyThreatIntelSummaryValid) {
        const retainedBySeverity = retainedThreatFindings.reduce<Record<Exclude<RiskLevel, "unknown">, number>>((counts, item) => { counts[item.finding.severity] += 1; return counts; }, { low: 0, medium: 0, high: 0, critical: 0 });
        const counts = features.repository.dependencyThreatIntelCountsBySeverity;
        const omittedCritical = counts.critical > retainedBySeverity.critical;
        const omittedHigh = counts.high > retainedBySeverity.high;
        if (omittedCritical || omittedHigh) push(signals, "THREAT_INTELLIGENCE_MATCH", omittedCritical ? "critical" : "high", "OMNI threat intelligence", { observedCountsBySeverity: counts, retainedDetailCount: retainedThreatFindings.length, summaryStatus: features.repository.dependencyThreatIntelSummaryStatus });
      }
      if (repositoryThreatIntelRisk > 0 || retainedThreatFindings.length > 0) repositoryMaliciousInfrastructure = scoreLevel(repositoryThreatIntelRisk, policy);
      else if (features.repository.dependencyThreatIntelStatus === "CHECKED" && features.repository.dependencyThreatIntelSummaryValid) repositoryMaliciousInfrastructure = "low";
      else repositoryMaliciousInfrastructure = "unknown";
      if (repositorySecurityPracticeRisk !== undefined) repositorySecurityPractices = scoreLevel(repositorySecurityPracticeRisk, policy);
    }

    let maliciousInfrastructureRisk: number | undefined;
    if (!isRepository && !isAgent && features.threatIntel.checked) {
      maliciousInfrastructureRisk = 0;
      for (const finding of features.threatIntel.findings) {
        const weight = policy.threatIntel[finding.severity];
        maliciousInfrastructureRisk = Math.max(maliciousInfrastructureRisk, weight);
        push(signals, "THREAT_INTELLIGENCE_MATCH", finding.severity, finding.source, { indicatorType: finding.indicatorType, threatType: finding.threatType, ...(finding.reference ? { reference: finding.reference } : {}) });
      }
    }

    let identityRisk: number | undefined;
    let endpointRisk: number | undefined;
    if (!isAgent && features.endpoint.present) {
      identityRisk = features.endpoint.listedOnCircle === true ? 0 : features.endpoint.listedOnCircle === false ? policy.endpoint.unlisted : undefined;
      if (features.endpoint.listedOnCircle === false) push(signals, "NOT_LISTED_IN_CIRCLE_DISCOVERY", "medium", "Circle Discovery", {});
      endpointRisk = 0;
      if (features.endpoint.responseStatus !== undefined && features.endpoint.responseStatus >= 500) { endpointRisk += policy.endpoint.serverError; push(signals, "ENDPOINT_SERVER_ERROR", "medium", "OMNI active probe", { status: features.endpoint.responseStatus }); }
      if (features.endpoint.responseStatus !== undefined && features.endpoint.responseStatus !== 402) { endpointRisk += policy.endpoint.handshakeMissing; push(signals, "X402_HANDSHAKE_NOT_OBSERVED", "low", "OMNI active probe", { status: features.endpoint.responseStatus }); }
      if (features.endpoint.supportsGateway === false && features.endpoint.supportsVanilla === false) { endpointRisk += policy.endpoint.noSupportedPath; push(signals, "NO_SUPPORTED_X402_PATH", "medium", "Circle Discovery", {}); }
    }

    let paymentRisk: number | undefined;
    if (!isAgent && features.history.checked) {
      paymentRisk = 0;
      if (features.history.payToChangeCount > 0) { paymentRisk += policy.payment.payToChange; push(signals, "PAYMENT_DESTINATION_CHANGED", "high", "OMNI history", { changeCount: features.history.payToChangeCount }); }
      if (features.history.networkChangeCount > 0) { paymentRisk += policy.payment.networkChange; push(signals, "PAYMENT_NETWORK_CHANGED", "medium", "OMNI history", { changeCount: features.history.networkChangeCount }); }
      if (features.history.priceChangeCount > 0) { paymentRisk += policy.payment.priceChange; push(signals, "PRICE_CONFIGURATION_CHANGED", "low", "OMNI history", { changeCount: features.history.priceChangeCount }); }
      if (features.history.schemaChangeCount > 0) { paymentRisk += policy.payment.schemaChange; push(signals, "SERVICE_SCHEMA_CHANGED", "low", "OMNI history", { changeCount: features.history.schemaChangeCount }); }
      if (features.history.providerChangeCount > 0) { paymentRisk += policy.payment.providerChange; push(signals, "PROVIDER_IDENTITY_CHANGED", "medium", "OMNI history", { changeCount: features.history.providerChangeCount }); }
    }

    const coverage = features.coverage.expected === 0 ? 0 : features.coverage.completed / features.coverage.expected;
    const status = scoreStatus(features);
    const sourcePenalty = isRepository || isAgent ? 0 : Math.min(policy.score.sourceErrorPenaltyCap, features.sourceErrorCount * policy.score.sourceErrorPenalty);
    const observedRisk = isRepository
      ? Math.max(repositorySecurityPracticeRisk ?? 0, repositoryVulnerabilityRisk ?? 0, repositoryKnownExploitationRisk ?? 0, repositoryMaliciousPackageRisk ?? 0, repositoryThreatIntelRisk ?? 0)
      : isAgent
        ? 0 // agent scoring handled above in assessAgentFeatures
        : Math.max(maxVulnScore, exploitedScore, packageRisk ?? 0, maliciousInfrastructureRisk ?? 0, identityRisk ?? 0, paymentRisk ?? 0, endpointRisk ?? 0) + sourcePenalty;
    let score = Math.min(policy.score.maximum, Math.max(policy.score.minimum, observedRisk));
    if (!isRepository && !isAgent && coverage === 0) score = Math.max(score, policy.score.zeroCoverageFloor);
    else if (!isRepository && !isAgent && snapshot.subject.type !== "package" && coverage < 1 && features.sourceErrorCount > 0) score = Math.max(score, policy.score.partialCoverageFloor);
    else if (!isRepository && !isAgent && snapshot.subject.type === "package" && features.coverage.sources?.some(source => source.source === "OSV" && (source.status === "UNAVAILABLE" || source.status === "UNKNOWN"))) score = Math.max(score, policy.recommendationThresholds.manualReview);

    const knownVulnerabilities: RiskLevel = isRepository ? repositoryKnownVulnerabilities : features.vulnerabilities === undefined ? "unknown" : features.vulnerabilities.length === 0 ? "low" : worstSeverity(features.vulnerabilities.map(v => v.severity), policy);
    const knownExploitation: RiskLevel = isRepository ? repositoryKnownExploitation : features.vulnerabilities === undefined ? "unknown" : features.vulnerabilities.length === 0 ? "low" : features.exploitationChecked ? scoreLevel(exploitedScore, policy) : "unknown";
    const summary = repositoryRiskSummary(snapshot, features, policy);
    return {
      subject: snapshot.subject,
      policyVersion: policy.version,
      scoreStatus: status,
      recommendation: recommendation(score, policy, status, snapshot.subject.type),
      riskScore: score,
      evidenceCoverage: Number(coverage.toFixed(2)),
      ...(features.coverage.modelVersion && features.coverage.sources ? { coverage: { modelVersion: features.coverage.modelVersion, resolvedWeight: features.coverage.completed, applicableWeight: features.coverage.expected, sources: features.coverage.sources } } : {}),
      dimensions: {
        knownVulnerabilities: isAgent ? "not_applicable" : knownVulnerabilities,
        knownExploitation: isAgent ? "not_applicable" : knownExploitation,
        packageSupplyChain: isRepository || isAgent ? "not_applicable" : packageRisk === undefined ? "unknown" : scoreLevel(packageRisk, policy),
        repositorySecurityPractices: isAgent ? "not_applicable" : isRepository ? repositorySecurityPractices : features.scorecard === undefined ? "unknown" : scoreLevel(0, policy),
        maliciousInfrastructure: isAgent ? "not_applicable" : isRepository ? repositoryMaliciousInfrastructure : maliciousInfrastructureRisk === undefined ? "unknown" : scoreLevel(maliciousInfrastructureRisk, policy),
        serviceIdentity: isRepository || isAgent ? "not_applicable" : identityRisk === undefined ? "unknown" : scoreLevel(identityRisk, policy),
        paymentConfigurationRisk: isRepository || isAgent ? "not_applicable" : paymentRisk === undefined ? "unknown" : scoreLevel(paymentRisk, policy),
        endpointOperationalRisk: isRepository || isAgent ? "not_applicable" : endpointRisk === undefined ? "unknown" : scoreLevel(endpointRisk, policy)
      },
      signals,
      evidence: snapshot.evidence,
      sourceErrors: snapshot.sourceErrors ?? [],
      assessedAt: new Date().toISOString(),
      ...(summary === undefined ? {} : { repositorySummary: summary }),
      ...(snapshot.maliciousPackageObservations ? { maliciousPackageObservations: snapshot.maliciousPackageObservations } : {}),
      freshness: freshness(snapshot.evidence)
    };
  }
}
