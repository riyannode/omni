import type { EvidenceCoverageSource, ProvenanceState, RepositoryDependencyVulnerabilityFinding, RepositoryDependencyVulnerabilityStatus, RepositoryDependencyVulnerabilitySummary, RepositoryMaliciousPackageObservation, RepositorySummaryStatus, RepositoryThreatIntelFinding, RepositoryThreatIntelStatus, RepositoryThreatIntelSummary, RiskLevel, RiskSnapshot, ThreatFinding, VulnerabilityFinding } from "./risk.ts";

export const RISK_FEATURE_SCHEMA_VERSION = 4 as const;

type KnownSeverity = Exclude<RiskLevel, "unknown">;
type SeverityCounts = Record<KnownSeverity, number>;
type VulnerabilitySeverityCounts = Record<RiskLevel, number>;

export type RiskFeatures = {
  schemaVersion: typeof RISK_FEATURE_SCHEMA_VERSION;
  subject: RiskSnapshot["subject"];
  vulnerabilities: VulnerabilityFinding[] | undefined;
  vulnerabilityCount: number;
  knownExploitedVulnerabilityCount: number;
  maximumVulnerabilitySeverity: RiskLevel | undefined;
  exploitationChecked: boolean;
  package: { present: boolean; deprecated: boolean; installLifecycleScript: boolean; integrityPresent: boolean; maintainerCount: number | undefined };
  repository: {
    present: boolean;
    partial: boolean;
    installLifecycleScriptCount: number;
    downloadExecutePatternCount: number;
    mutableActionRefCount: number;
    workflowWritePermissionCount: number;
    exactDependencyCount: number;
    unresolvedDependencyCount: number;
    inspectedSecurityFileCount: number;
    provenanceStates: Record<ProvenanceState, number>;
    dependencyVulnerabilityStatus: RepositoryDependencyVulnerabilityStatus | undefined;
    dependencyVulnerabilitySummaryStatus: RepositorySummaryStatus;
    dependencyVulnerabilitySummaryValid: boolean;
    dependencyVulnerabilityCountsBySeverity: VulnerabilitySeverityCounts;
    knownExploitedDependencyVulnerabilityCount: number;
    maliciousPackageObservationCount: number;
    retainedDependencyVulnerabilities: RepositoryDependencyVulnerabilityFinding[];
    retainedMaliciousPackageObservations: RepositoryMaliciousPackageObservation[];
    cisaKevStatus: "NOT_QUERIED" | "CHECKED" | "UNAVAILABLE" | "UNKNOWN";
    cisaKevMatchedCount: number;
    cisaKevCorrelatableCount: number;
    dependencyThreatIntelStatus: RepositoryThreatIntelStatus | undefined;
    dependencyThreatIntelSummaryStatus: RepositorySummaryStatus;
    dependencyThreatIntelSummaryValid: boolean;
    dependencyThreatIntelCountsBySeverity: SeverityCounts;
    retainedDependencyThreatIntelFindings: RepositoryThreatIntelFinding[];
  };
  scorecard: number | undefined;
  threatIntel: { checked: boolean; findings: ThreatFinding[]; matchCount: number; countsBySeverity: SeverityCounts };
  endpoint: { present: boolean; listedOnCircle: boolean | undefined; supportsGateway: boolean | undefined; supportsVanilla: boolean | undefined; responseStatus: number | undefined };
  history: { checked: boolean; present: boolean; payToChangeCount: number; networkChangeCount: number; priceChangeCount: number; schemaChangeCount: number; providerChangeCount: number };
  sourceErrorCount: number;
  coverage: { completed: number; expected: number; modelVersion?: string; sources?: EvidenceCoverageSource[] };
  evidenceCount: number;
};

function validCoverageSources(sources: EvidenceCoverageSource[]): boolean {
  const identities = new Set<string>();
  return Array.isArray(sources) && sources.every(source => {
    if (!source || typeof source !== "object" || typeof source.source !== "string" || source.source.length === 0 || identities.has(source.source) || !Number.isFinite(source.weight) || source.weight <= 0) return false;
    if (source.execution !== "QUERIED" && source.execution !== "NOT_QUERIED") return false;
    if (!["OBSERVED", "ABSENT", "UNAVAILABLE", "UNKNOWN", "NOT_APPLICABLE"].includes(source.status)) return false;
    identities.add(source.source);
    if (source.status === "NOT_APPLICABLE") return source.execution === "NOT_QUERIED";
    if (source.execution === "NOT_QUERIED") return source.status === "UNKNOWN";
    return true;
  });
}

function summaryIsValid(summary: RepositoryDependencyVulnerabilitySummary | RepositoryThreatIntelSummary | undefined): boolean {
  if (!summary || (summary.status !== "VALID" && summary.status !== "TRUNCATED") || !Number.isSafeInteger(summary.findingsObserved) || summary.findingsObserved < 0) return false;
  const counts = Object.values(summary.countsBySeverity);
  if (counts.some(value => !Number.isSafeInteger(value) || value < 0) || counts.reduce((total, value) => total + value, 0) !== summary.findingsObserved) return false;
  if ("knownExploitedObserved" in summary && (!Number.isSafeInteger(summary.knownExploitedObserved) || summary.knownExploitedObserved < 0 || summary.knownExploitedObserved > summary.findingsObserved)) return false;
  if ("maliciousPackageObservationsObserved" in summary && (!Number.isSafeInteger(summary.maliciousPackageObservationsObserved) || summary.maliciousPackageObservationsObserved < 0)) return false;
  return true;
}

function emptyVulnerabilityCounts(): VulnerabilitySeverityCounts {
  return { unknown: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

function emptyThreatCounts(): SeverityCounts {
  return { low: 0, medium: 0, high: 0, critical: 0 };
}

function vulnerabilityCounts(summary: RepositoryDependencyVulnerabilitySummary | undefined): VulnerabilitySeverityCounts {
  const result = emptyVulnerabilityCounts();
  if (!summary || typeof summary !== "object" || !("countsBySeverity" in summary) || !summary.countsBySeverity || typeof summary.countsBySeverity !== "object") return result;
  for (const level of Object.keys(result) as RiskLevel[]) {
    const value = (summary.countsBySeverity as Record<string, unknown>)[level];
    if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) result[level] = value;
  }
  return result;
}

function threatCounts(summary: RepositoryThreatIntelSummary | undefined): SeverityCounts {
  const result = emptyThreatCounts();
  if (!summary || typeof summary !== "object" || !("countsBySeverity" in summary) || !summary.countsBySeverity || typeof summary.countsBySeverity !== "object") return result;
  for (const level of Object.keys(result) as KnownSeverity[]) {
    const value = (summary.countsBySeverity as Record<string, unknown>)[level];
    if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) result[level] = value;
  }
  return result;
}

export function extractRiskFeatures(snapshot: RiskSnapshot): RiskFeatures {
  const vulnerabilities = snapshot.vulnerabilities;
  const threatFindings = snapshot.threatFindings ?? [];
  const ranks: Record<RiskLevel, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const maximumVulnerabilitySeverity = vulnerabilities?.some(vulnerability => vulnerability.severity === "unknown")
    ? "unknown"
    : vulnerabilities?.reduce<RiskLevel | undefined>((maximum, vulnerability) => !maximum || ranks[vulnerability.severity] > ranks[maximum] ? vulnerability.severity : maximum, undefined);
  const countsBySeverity = emptyThreatCounts();
  for (const finding of threatFindings) countsBySeverity[finding.severity] += 1;

  let expected = 0; let completed = 0;
  if (snapshot.coverage && validCoverageSources(snapshot.coverage.sources)) {
    const applicable = snapshot.coverage.sources.filter(source => source.status !== "NOT_APPLICABLE");
    expected = applicable.reduce((total, source) => total + source.weight, 0);
    completed = applicable.reduce((total, source) => total + (source.status === "OBSERVED" || source.status === "ABSENT" ? source.weight : 0), 0);
  } else if (snapshot.coverage) {
    expected = 0;
    completed = 0;
  } else {
    switch (snapshot.subject.type) {
      case "package": { const checks = [vulnerabilities !== undefined, snapshot.exploitationChecked === true]; if (snapshot.packageSupplyChain) checks.push(true); if (snapshot.threatIntelChecked !== undefined) checks.push(snapshot.threatIntelChecked); expected = checks.length; completed = checks.filter(Boolean).length; break; }
      case "repository": expected = 1; completed = snapshot.scorecard === undefined ? 0 : 1; break;
      case "x402_endpoint": { const checks = [snapshot.endpoint?.listedOnCircle !== undefined, snapshot.activeProbeChecked === true, snapshot.historyChecked === true, snapshot.threatIntelChecked === true]; expected = checks.length; completed = checks.filter(Boolean).length; break; }
      case "dependency_set": expected = 1; completed = snapshot.evidence.length === 0 ? 0 : 1; break;
    }
  }

  const repositoryEvidence = snapshot.repositoryEvidence;
  const vulnerabilityObservation = repositoryEvidence?.dependencyVulnerabilities;
  const threatObservation = repositoryEvidence?.dependencyThreatIntel;
  const vulnerabilitySummaryStatus = vulnerabilityObservation?.summary?.status ?? "MISSING";
  const threatSummaryStatus = threatObservation?.summary?.status ?? "MISSING";
  const provenanceStates = { NOT_CHECKED: 0, UNAVAILABLE: 0, PRESENT_UNVERIFIED: 0, VERIFIED: 0, VERIFIED_SOURCE_MISMATCH: 0, VERIFIED_COMMIT_MISMATCH: 0, VERIFIED_COMMIT_UNCONFIRMED: 0, ERROR: 0 } as Record<ProvenanceState, number>;
  for (const observation of repositoryEvidence?.dependencyObservations?.flatMap(item => item.provenance) ?? []) provenanceStates[observation.state] += 1;
  const count = (finding: string) => repositoryEvidence?.securityFiles.reduce((total, file) => total + file.findings.filter(item => item === finding).length, 0) ?? 0;
  const inspectedSecurityFileCount = repositoryEvidence?.securityFiles.filter(file => file.status === "inspected").length ?? 0;

  return {
    schemaVersion: RISK_FEATURE_SCHEMA_VERSION,
    subject: snapshot.subject,
    vulnerabilities,
    vulnerabilityCount: vulnerabilities?.length ?? 0,
    knownExploitedVulnerabilityCount: vulnerabilities?.filter(item => item.knownExploited).length ?? 0,
    maximumVulnerabilitySeverity,
    exploitationChecked: snapshot.exploitationChecked === true,
    package: { present: snapshot.packageSupplyChain !== undefined, deprecated: snapshot.packageSupplyChain?.deprecated ?? false, installLifecycleScript: snapshot.packageSupplyChain?.hasInstallScript ?? false, integrityPresent: snapshot.packageSupplyChain?.integrityPresent ?? false, maintainerCount: snapshot.packageSupplyChain?.maintainerCount },
    repository: {
      present: repositoryEvidence !== undefined,
      partial: repositoryEvidence?.coverage.status === "partial",
      installLifecycleScriptCount: count("INSTALL_LIFECYCLE_SCRIPT"),
      downloadExecutePatternCount: count("DOWNLOAD_EXECUTE_PATTERN"),
      mutableActionRefCount: count("MUTABLE_GITHUB_ACTION_REF"),
      workflowWritePermissionCount: count("WORKFLOW_WRITE_PERMISSION"),
      exactDependencyCount: repositoryEvidence?.dependencies.exact.length ?? 0,
      unresolvedDependencyCount: repositoryEvidence?.dependencies.unresolved.length ?? 0,
      inspectedSecurityFileCount,
      provenanceStates,
      dependencyVulnerabilityStatus: vulnerabilityObservation?.status,
      dependencyVulnerabilitySummaryStatus: vulnerabilitySummaryStatus,
      dependencyVulnerabilitySummaryValid: summaryIsValid(vulnerabilityObservation?.summary),
      dependencyVulnerabilityCountsBySeverity: vulnerabilityCounts(vulnerabilityObservation?.summary),
      knownExploitedDependencyVulnerabilityCount: vulnerabilityObservation?.summary?.knownExploitedObserved ?? 0,
      maliciousPackageObservationCount: vulnerabilityObservation?.summary?.maliciousPackageObservationsObserved ?? 0,
      retainedDependencyVulnerabilities: vulnerabilityObservation?.findings ?? [],
      retainedMaliciousPackageObservations: vulnerabilityObservation?.maliciousPackageObservations ?? [],
      cisaKevStatus: vulnerabilityObservation?.cisaKev.status ?? "UNKNOWN",
      cisaKevMatchedCount: vulnerabilityObservation?.cisaKev.matchedCveIds.length ?? 0,
      cisaKevCorrelatableCount: vulnerabilityObservation?.cisaKev.correlatableCveIds.length ?? 0,
      dependencyThreatIntelStatus: threatObservation?.status,
      dependencyThreatIntelSummaryStatus: threatSummaryStatus,
      dependencyThreatIntelSummaryValid: summaryIsValid(threatObservation?.summary),
      dependencyThreatIntelCountsBySeverity: threatCounts(threatObservation?.summary),
      retainedDependencyThreatIntelFindings: threatObservation?.findings ?? []
    },
    scorecard: snapshot.scorecard,
    threatIntel: { checked: snapshot.threatIntelChecked === true, findings: threatFindings, matchCount: threatFindings.length, countsBySeverity },
    endpoint: { present: snapshot.endpoint !== undefined, listedOnCircle: snapshot.endpoint?.listedOnCircle, supportsGateway: snapshot.endpoint?.supportsGateway, supportsVanilla: snapshot.endpoint?.supportsVanilla, responseStatus: snapshot.endpoint?.responseStatus },
    history: { checked: snapshot.historyChecked === true && snapshot.endpointHistory !== undefined, present: snapshot.endpointHistory !== undefined, payToChangeCount: snapshot.endpointHistory?.payToChangeCount ?? 0, networkChangeCount: snapshot.endpointHistory?.networkChangeCount ?? 0, priceChangeCount: snapshot.endpointHistory?.priceChangeCount ?? 0, schemaChangeCount: snapshot.endpointHistory?.schemaChangeCount ?? 0, providerChangeCount: snapshot.endpointHistory?.providerChangeCount ?? 0 },
    sourceErrorCount: snapshot.sourceErrors?.length ?? 0,
    coverage: { completed, expected, ...(snapshot.coverage?.modelVersion ? { modelVersion: snapshot.coverage.modelVersion } : {}), ...(snapshot.coverage ? { sources: snapshot.coverage.sources } : {}) },
    evidenceCount: snapshot.evidence.length
  };
}
