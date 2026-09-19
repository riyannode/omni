import { REPOSITORY_COVERAGE_MODEL_VERSION, PACKAGE_COVERAGE_MODEL_VERSION, AGENT_COVERAGE_MODEL_VERSION, DEFAULT_AGENT_REPUTATION_POLICY, type AgentReputationPolicy, type AgentRisk, type AgentRiskAssessment, type AgentChainIdentityResult, type AgentReputationSummary, type DependencyObservation, type EvidenceCoverageSource, type ExactDependencyCoordinate, type RepositoryCollectionCoverage, type RepositoryDependencyVulnerabilityFinding, type RepositoryDependencyVulnerabilityObservation, type RepositoryDependencyVulnerabilitySummary, type RepositoryEvidence, type RepositoryThreatIntelObservation, type RepositoryThreatIntelFinding, type RepositoryThreatIntelSummary, type RiskAssessment, type RiskSnapshot, type ThreatFinding, type RiskLevel } from "./domain/risk.ts";
import { RiskEngine } from "./domain/risk-engine.ts";
import { RISK_POLICY_VERSION } from "./domain/risk-policy.ts";
import type { ObservedPaymentRequirement, X402EndpointPreflight } from "./domain/x402-preflight-consistency.ts";
import { CachedLoader } from "./data/cache.ts";
import type { HistoryStore } from "./data/history.ts";
import type { ThreatIntelStore } from "./data/threat-intel.ts";
import { extractRiskFeatures } from "./domain/risk-features.ts";
import type { AssessmentJournal } from "./data/assessment-journal.ts";
import { NoopAssessmentJournal } from "./data/assessment-journal.ts";
import { OsvProvider, repositoryOsvEcosystem } from "./providers/osv.ts";
import { CisaKevProvider } from "./providers/cisa-kev.ts";
import { ScorecardProvider, type ScorecardProviderResult } from "./providers/scorecard.ts";
import { GitHubRepositoryProvider } from "./providers/github-repository.ts";
import { DepsDevProvider } from "./providers/deps-dev.ts";
import { NpmRegistryProvider } from "./providers/npm-registry.ts";
import { CircleDiscoveryProvider } from "./providers/circle-discovery.ts";
import { X402Probe } from "./providers/x402-probe.ts";
import {
  ERC8004_PRODUCTION_CHAINS,
  readAgentIdentity,
  scanAgentReputation,
  fetchAgentCard,
  probeTargetUrlRedirectsToPrivate,
  extractServices,
  getChainConfig,
  type Erc8004ChainConfig,
  REPUTATION_DEFAULT_MAX_CHUNKS,
  NEW_FEEDBACK_TOPIC,
  FEEDBACK_REVOKED_TOPIC,
} from "./providers/erc8004.ts";

type AgentRiskProvider = {
  readAgentIdentity: typeof readAgentIdentity;
  scanAgentReputation: typeof scanAgentReputation;
  fetchAgentCard: typeof fetchAgentCard;
  probeTargetUrlRedirectsToPrivate: typeof probeTargetUrlRedirectsToPrivate;
};

const DEFAULT_AGENT_RISK_PROVIDER: AgentRiskProvider = {
  readAgentIdentity,
  scanAgentReputation,
  fetchAgentCard,
  probeTargetUrlRedirectsToPrivate,
};

const REPOSITORY_DEPENDENCY_ENRICHMENT_LIMIT = 24;
const REPOSITORY_ENRICHMENT_CONCURRENCY = 4;
const REPOSITORY_ASSESSMENT_CACHE_TTL_SECONDS = 600;
export const MAX_REPOSITORY_OSV_FINDINGS_PER_PACKAGE = 16;
export const MAX_REPOSITORY_OSV_FINDINGS_TOTAL = 128;
export const MAX_REPOSITORY_OSV_MALICIOUS_OBSERVATIONS_TOTAL = 128;
export const MAX_REPOSITORY_OSV_ERROR_ENTRIES = 16;
export const MAX_REPOSITORY_OSV_LIMITATION_ENTRIES = 16;
export const MAX_REPOSITORY_OSV_ENTRY_BYTES = 512;
export const MAX_REPOSITORY_OSV_BYTES = 64 * 1024;
export const MAX_REPOSITORY_THREAT_FINDINGS_PER_PACKAGE = 8;
export const MAX_REPOSITORY_THREAT_FINDINGS_TOTAL = 64;
export const MAX_REPOSITORY_THREAT_INTEL_BYTES = 64 * 1024;
export const MAX_REPOSITORY_THREAT_INTEL_INDICATOR_BYTES = 1024;
export const MAX_REPOSITORY_THREAT_INTEL_THREAT_TYPE_BYTES = 256;
export const MAX_REPOSITORY_THREAT_INTEL_SOURCE_BYTES = 256;
export const MAX_REPOSITORY_THREAT_INTEL_REFERENCE_BYTES = 2048;
export const MAX_REPOSITORY_THREAT_INTEL_ERROR_ENTRIES = 8;
export const MAX_REPOSITORY_THREAT_INTEL_LIMITATION_ENTRIES = 16;
export const MAX_REPOSITORY_THREAT_INTEL_ENTRY_BYTES = 512;

function coordinateIdentity(coordinate: { ecosystem: string; name: string; version: string }): string { return `${coordinate.ecosystem}:${coordinate.name}@${coordinate.version}`; }

function cachePart(value: string): string { return `${value.length}:${value}`; }

function coverageSource(source: string, execution: EvidenceCoverageSource["execution"], status: EvidenceCoverageSource["status"]): EvidenceCoverageSource {
  return { source, execution, status, weight: 1 };
}

function decimalParts(value: string | number): { coefficient: bigint; scale: number } | undefined {
  const text = String(value);
  const match = /^(?<sign>-?)(?<whole>\d+)(?:\.(?<fraction>\d+))?$/.exec(text);
  if (!match?.groups) return undefined;
  const fraction = match.groups.fraction ?? "";
  if (fraction.length > 18) return undefined;
  const coefficient = BigInt(`${match.groups.sign === "-" ? "-" : ""}${match.groups.whole}${fraction}`);
  return { coefficient, scale: fraction.length };
}

function thresholdBreached(value: bigint, valueDecimals: number, policy: AgentReputationPolicy["recognizedTags"][number]): boolean {
  const threshold = decimalParts(policy.threshold);
  if (!threshold || valueDecimals < 0 || valueDecimals > 18) return false;
  const left = value * (10n ** BigInt(threshold.scale));
  const right = threshold.coefficient * (10n ** BigInt(valueDecimals));
  return policy.direction === "higher_is_better" ? left < right : left > right;
}

function githubCollectionFallback(repositoryEvidence: RepositoryEvidence): RepositoryCollectionCoverage {
  const limitations = repositoryEvidence.coverage.limitations.filter(item => item === "github_collection_unavailable" || item === "github_tree_truncated" || item === "tree_entry_limit_reached" || item === "security_file_limit_reached" || item.startsWith("security_file_") || item.startsWith("github_"));
  return { status: limitations.length === 0 ? "complete" : "partial", limitations, sourceErrors: repositoryEvidence.sourceErrors.filter(error => error.startsWith("GitHub:")) };
}

function repositoryDependencyResolutionCoverage(repositoryEvidence: RepositoryEvidence, githubCollection: RepositoryCollectionCoverage): EvidenceCoverageSource {
  const resolution = repositoryEvidence.dependencyResolution;
  if (resolution) {
    const hasApplicableExternalDependencies = resolution.applicableExternalDependencyCount > 0;
    const execution = resolution.resolversAttempted.length > 0 ? "QUERIED" : "NOT_QUERIED";
    if (!hasApplicableExternalDependencies && resolution.manifestDiscoveryComplete && resolution.unsupportedEcosystems.length === 0 && resolution.unresolvedDependencyCount === 0) {
      return coverageSource("Dependency Resolution", "NOT_QUERIED", "NOT_APPLICABLE");
    }
    if (execution === "NOT_QUERIED") return coverageSource("Dependency Resolution", "NOT_QUERIED", "UNKNOWN");
    const complete = resolution.manifestDiscoveryComplete && resolution.unsupportedEcosystems.length === 0 && resolution.unresolvedDependencyCount === 0;
    return coverageSource("Dependency Resolution", "QUERIED", complete ? "OBSERVED" : "UNKNOWN");
  }
  const limitations = repositoryEvidence.coverage.limitations;
  const hasDependencies = repositoryEvidence.dependencies.exact.length > 0 || repositoryEvidence.dependencies.unresolved.length > 0;
  const resolverAttempted = repositoryEvidence.dependencies.unresolved.length > 0
    || limitations.some(item => item.startsWith("dependency_lock_") || item === "dependency_versions_unresolved");
  const unsupported = limitations.some(item => item.startsWith("dependency_resolution_unsupported:"));
  const resolutionIsIncomplete = resolverAttempted || unsupported || limitations.includes("dependency_resolution_unavailable");
  if (!hasDependencies && !resolutionIsIncomplete && githubCollection.status !== "complete") return coverageSource("Dependency Resolution", "NOT_QUERIED", "UNKNOWN");
  if (!hasDependencies && !resolutionIsIncomplete) return coverageSource("Dependency Resolution", "NOT_QUERIED", "NOT_APPLICABLE");
  if (resolverAttempted) return coverageSource("Dependency Resolution", "QUERIED", "UNKNOWN");
  if (unsupported || limitations.includes("dependency_resolution_unavailable")) return coverageSource("Dependency Resolution", "NOT_QUERIED", "UNKNOWN");
  return coverageSource("Dependency Resolution", "QUERIED", "OBSERVED");
}

const observedProvenanceStates = new Set(["PRESENT_UNVERIFIED", "VERIFIED", "VERIFIED_SOURCE_MISMATCH", "VERIFIED_COMMIT_MISMATCH", "VERIFIED_COMMIT_UNCONFIRMED"]);

function repositoryDependencyProvenanceCoverage(repositoryEvidence: RepositoryEvidence, dependencyResolution: EvidenceCoverageSource, enrichedCount: number, deferred: number): EvidenceCoverageSource {
  if (dependencyResolution.status === "NOT_APPLICABLE") return coverageSource("deps.dev Provenance", "NOT_QUERIED", "NOT_APPLICABLE");
  if (enrichedCount === 0) return coverageSource("deps.dev Provenance", "NOT_QUERIED", "UNKNOWN");
  if (dependencyResolution.status === "UNKNOWN") return coverageSource("deps.dev Provenance", "QUERIED", "UNKNOWN");
  const providerFailures = repositoryEvidence.sourceErrors.filter(error => error.startsWith("deps.dev ")).length;
  if (deferred > 0) return coverageSource("deps.dev Provenance", "QUERIED", "UNKNOWN");
  if (providerFailures > 0) return coverageSource("deps.dev Provenance", "QUERIED", providerFailures >= enrichedCount && repositoryEvidence.dependencyObservations.length === 0 ? "UNAVAILABLE" : "UNKNOWN");
  if (repositoryEvidence.dependencyObservations.length < enrichedCount) return coverageSource("deps.dev Provenance", "QUERIED", "UNKNOWN");
  if (repositoryEvidence.dependencyObservations.length === 0) return coverageSource("deps.dev Provenance", "QUERIED", "UNKNOWN");
  const states = repositoryEvidence.dependencyObservations.flatMap(observation => observation.provenance.map(item => item.state));
  if (states.some(state => observedProvenanceStates.has(state))) {
    return coverageSource("deps.dev Provenance", "QUERIED", states.every(state => observedProvenanceStates.has(state) || state === "UNAVAILABLE") ? "OBSERVED" : "UNKNOWN");
  }
  if (states.length === 0 || states.every(state => state === "UNAVAILABLE")) return coverageSource("deps.dev Provenance", "QUERIED", "ABSENT");
  return coverageSource("deps.dev Provenance", "QUERIED", "UNKNOWN");
}

function repositoryThreatIntelCoverage(repositoryEvidence: RepositoryEvidence, dependencyResolution: EvidenceCoverageSource, enrichedCount: number, deferred: number): EvidenceCoverageSource {
  if (dependencyResolution.status === "NOT_APPLICABLE") return coverageSource("Threat Intelligence", "NOT_QUERIED", "NOT_APPLICABLE");
  if (enrichedCount === 0) return coverageSource("Threat Intelligence", "NOT_QUERIED", "UNKNOWN");
  if (dependencyResolution.status === "UNKNOWN") return coverageSource("Threat Intelligence", "QUERIED", "UNKNOWN");
  if (repositoryEvidence.dependencyThreatIntel.status === "UNAVAILABLE") return coverageSource("Threat Intelligence", "QUERIED", "UNAVAILABLE");
  if (repositoryEvidence.dependencyThreatIntel.status === "UNKNOWN") return coverageSource("Threat Intelligence", "QUERIED", "UNKNOWN");
  if (deferred > 0 || repositoryEvidence.dependencyThreatIntel.status === "NOT_CHECKED") return coverageSource("Threat Intelligence", "QUERIED", "UNKNOWN");
  return coverageSource("Threat Intelligence", "QUERIED", repositoryEvidence.dependencyThreatIntel.findings.length > 0 ? "OBSERVED" : "ABSENT");
}

function repositoryDependencyVulnerabilityCoverage(repositoryEvidence: RepositoryEvidence, dependencyResolution: EvidenceCoverageSource, enrichedCount: number, deferred: number): EvidenceCoverageSource {
  const observation = repositoryEvidence.dependencyVulnerabilities;
  if (dependencyResolution.status === "NOT_APPLICABLE") return coverageSource("OSV Dependency Vulnerabilities", "NOT_QUERIED", "NOT_APPLICABLE");
  if (enrichedCount === 0) return coverageSource("OSV Dependency Vulnerabilities", "NOT_QUERIED", "UNKNOWN");
  if (dependencyResolution.status === "UNKNOWN" || deferred > 0) return coverageSource("OSV Dependency Vulnerabilities", "QUERIED", "UNKNOWN");
  if (observation.status === "UNAVAILABLE") return coverageSource("OSV Dependency Vulnerabilities", "QUERIED", "UNAVAILABLE");
  if (observation.status !== "CHECKED") return coverageSource("OSV Dependency Vulnerabilities", "QUERIED", "UNKNOWN");
  if (observation.limitations.some(item => item.startsWith("repository_osv_") || item.startsWith("dependency_enrichment_limit_reached:"))) return coverageSource("OSV Dependency Vulnerabilities", "QUERIED", "UNKNOWN");
  return coverageSource("OSV Dependency Vulnerabilities", "QUERIED", observation.findings.length > 0 || observation.maliciousPackageObservations.length > 0 ? "OBSERVED" : "ABSENT");
}

function repositoryDependencyKevCoverage(repositoryEvidence: RepositoryEvidence, dependencyResolution: EvidenceCoverageSource, osvCoverage: EvidenceCoverageSource, enrichedCount: number, deferred: number): EvidenceCoverageSource {
  const observation = repositoryEvidence.dependencyVulnerabilities;
  if (dependencyResolution.status === "NOT_APPLICABLE") return coverageSource("CISA KEV", "NOT_QUERIED", "NOT_APPLICABLE");
  if (enrichedCount === 0) return coverageSource("CISA KEV", "NOT_QUERIED", "UNKNOWN");
  const incomplete = dependencyResolution.status === "UNKNOWN" || deferred > 0 || osvCoverage.status === "UNKNOWN";
  if (incomplete) return coverageSource("CISA KEV", observation.cisaKev.status === "CHECKED" || observation.cisaKev.status === "UNAVAILABLE" ? "QUERIED" : "NOT_QUERIED", "UNKNOWN");
  if (observation.cisaKev.status === "NOT_QUERIED") return coverageSource("CISA KEV", "NOT_QUERIED", "NOT_APPLICABLE");
  if (observation.cisaKev.status === "UNAVAILABLE") return coverageSource("CISA KEV", "QUERIED", "UNAVAILABLE");
  if (observation.cisaKev.status !== "CHECKED") return coverageSource("CISA KEV", "NOT_QUERIED", "UNKNOWN");
  return coverageSource("CISA KEV", "QUERIED", observation.cisaKev.matchedCveIds.length > 0 ? "OBSERVED" : "ABSENT");
}

function repositoryCoverage(repositoryEvidence: RepositoryEvidence, scorecardResult: ScorecardProviderResult, enrichedCount: number, deferred: number, githubCollection: RepositoryCollectionCoverage): EvidenceCoverageSource[] {
  const githubUnavailable = githubCollection.limitations.includes("github_collection_unavailable")
    || githubCollection.sourceErrors.some(error => error.startsWith("GitHub:"));
  const githubStatus = githubUnavailable
    ? "UNAVAILABLE"
    : githubCollection.status === "partial"
      ? "UNKNOWN"
      : "OBSERVED";
  const scorecardStatus = scorecardResult.status === "available"
    ? "OBSERVED"
    : scorecardResult.status === "unavailable"
      ? "UNAVAILABLE"
      : "UNKNOWN";
  const dependencyResolution = repositoryDependencyResolutionCoverage(repositoryEvidence, githubCollection);
  const osv = repositoryDependencyVulnerabilityCoverage(repositoryEvidence, dependencyResolution, enrichedCount, deferred);
  return [
    coverageSource("GitHub Repository Evidence", "QUERIED", githubStatus),
    coverageSource("OpenSSF Scorecard", "QUERIED", scorecardStatus),
    dependencyResolution,
    osv,
    repositoryDependencyKevCoverage(repositoryEvidence, dependencyResolution, osv, enrichedCount, deferred),
    repositoryDependencyProvenanceCoverage(repositoryEvidence, dependencyResolution, enrichedCount, deferred),
    repositoryThreatIntelCoverage(repositoryEvidence, dependencyResolution, enrichedCount, deferred)
  ];
}

function correlatableVulnerabilityIds(vulnerabilities: NonNullable<RiskSnapshot["vulnerabilities"]>): string[] {
  return [...new Set(vulnerabilities.flatMap(vulnerability => [vulnerability.id, ...vulnerability.aliases]).filter(id => /^CVE-\d{4}-\d+$/i.test(id)))].sort();
}

const threatSeverityRank: Record<ThreatFinding["severity"], number> = { low: 1, medium: 2, high: 3, critical: 4 };
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function compareText(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }
function utf8Bytes(value: string): number { return encoder.encode(value).byteLength; }

const coordinateFields: Array<keyof ExactDependencyCoordinate> = ["ecosystem", "name", "version", "sourcePath", "manifestPath", "workspacePath"];

function compareCoordinates(left: ExactDependencyCoordinate, right: ExactDependencyCoordinate): number {
  for (const field of coordinateFields) {
    const result = compareText(left[field], right[field]);
    if (result !== 0) return result;
  }
  return 0;
}

function compareRepositoryVulnerabilityFinding(left: RepositoryDependencyVulnerabilityFinding, right: RepositoryDependencyVulnerabilityFinding): number {
  return compareCoordinates(left.coordinate, right.coordinate)
    || compareText(left.vulnerability.id, right.vulnerability.id)
    || compareText(JSON.stringify(left), JSON.stringify(right));
}

function uniqueRepositoryVulnerabilityFindings(findings: RepositoryDependencyVulnerabilityFinding[]): RepositoryDependencyVulnerabilityFinding[] {
  const unique = new Map<string, RepositoryDependencyVulnerabilityFinding>();
  for (const finding of findings) {
    const sources = [...new Set(finding.sources)].sort(compareText) as RepositoryDependencyVulnerabilityFinding["sources"];
    const normalized = { ...finding, sources };
    const key = JSON.stringify(normalized);
    if (!unique.has(key)) unique.set(key, normalized);
  }
  return [...unique.values()].sort(compareRepositoryVulnerabilityFinding);
}

function repositoryVulnerabilitySummary(status: RepositoryDependencyVulnerabilitySummary["status"], findings: RepositoryDependencyVulnerabilityFinding[], maliciousPackageObservations: RepositoryDependencyVulnerabilityObservation["maliciousPackageObservations"]): RepositoryDependencyVulnerabilitySummary {
  const countsBySeverity = { unknown: 0, low: 0, medium: 0, high: 0, critical: 0 } as Record<RiskLevel, number>;
  for (const finding of findings) countsBySeverity[finding.vulnerability.severity] += 1;
  return { status, findingsObserved: findings.length, countsBySeverity, knownExploitedObserved: findings.filter(finding => finding.vulnerability.knownExploited).length, maliciousPackageObservationsObserved: maliciousPackageObservations.length };
}

function repositoryThreatIntelSummary(status: RepositoryThreatIntelSummary["status"], findings: RepositoryThreatIntelFinding[]): RepositoryThreatIntelSummary {
  const countsBySeverity = { low: 0, medium: 0, high: 0, critical: 0 } as Record<Exclude<RiskLevel, "unknown">, number>;
  for (const finding of findings) countsBySeverity[finding.finding.severity] += 1;
  return { status, findingsObserved: findings.length, countsBySeverity };
}

function threatIntelDetailWasTruncated(limitation: string): boolean {
  return limitation === "threat_intel_payload_truncated"
    || limitation.startsWith("threat_intel_finding_field_truncated:")
    || limitation.startsWith("threat_intel_findings_truncated:")
    || limitation.startsWith("threat_intel_total_findings_truncated:")
    || limitation.startsWith("threat_intel_packages_inspected_truncated:");
}

function vulnerabilityIdentity(finding: RepositoryDependencyVulnerabilityFinding): string {
  return `${coordinateIdentity(finding.coordinate)}:${finding.vulnerability.id}`;
}

function boundedRepositoryOsvStrings(values: string[], maximumEntries: number, label: "errors" | "limitations"): { values: string[]; overflow: boolean; entryTruncated: boolean } {
  let entryTruncated = false;
  const normalized = [...new Set(values.map(value => {
    const bounded = truncateUtf8(value, MAX_REPOSITORY_OSV_ENTRY_BYTES);
    entryTruncated ||= bounded.truncated;
    return bounded.value;
  }))].sort(compareText);
  const overflow = normalized.length > maximumEntries;
  const marker = `repository_osv_${label}_truncated:${maximumEntries}_of_${normalized.length}`;
  const retained = overflow ? [...normalized.slice(0, Math.max(0, maximumEntries - 1)), marker] : normalized;
  return { values: [...new Set(retained)].sort(compareText), overflow, entryTruncated };
}

function repositoryOsvIdentity(coordinate: ExactDependencyCoordinate): string {
  return `${coordinate.name}@${coordinate.version}`;
}

function fitRepositoryDependencyVulnerabilityObservation(observation: RepositoryDependencyVulnerabilityObservation): RepositoryDependencyVulnerabilityObservation {
  let packagesInspected = [...observation.packagesInspected].sort(compareCoordinates);
  let findings = [...observation.findings].sort(compareRepositoryVulnerabilityFinding);
  let maliciousPackageObservations = [...observation.maliciousPackageObservations].sort((left, right) => compareCoordinates(left.coordinate, right.coordinate) || compareText(left.id, right.id));
  let limitations = [...observation.limitations].sort(compareText);
  let summary = observation.summary;
  const result = (): RepositoryDependencyVulnerabilityObservation => ({ ...observation, ...(summary ? { summary } : {}), packagesInspected, findings, maliciousPackageObservations, limitations });
  if (utf8Bytes(JSON.stringify(result())) <= MAX_REPOSITORY_OSV_BYTES) return result();

  limitations = [...new Set([...limitations, "repository_osv_payload_truncated"])].sort(compareText);
  if (summary) summary = { ...summary, status: "TRUNCATED" };
  while (utf8Bytes(JSON.stringify(result())) > MAX_REPOSITORY_OSV_BYTES && findings.length > 0) findings.pop();
  while (utf8Bytes(JSON.stringify(result())) > MAX_REPOSITORY_OSV_BYTES && maliciousPackageObservations.length > 0) maliciousPackageObservations.pop();
  while (utf8Bytes(JSON.stringify(result())) > MAX_REPOSITORY_OSV_BYTES && packagesInspected.length > 0) packagesInspected.pop();
  if (utf8Bytes(JSON.stringify(result())) <= MAX_REPOSITORY_OSV_BYTES) return result();
  return { ...result(), packagesInspected: [], findings: [], maliciousPackageObservations: [], errors: [], limitations: ["repository_osv_payload_reduction_failed"] };
}

function finalizeRepositoryDependencyVulnerabilityObservation(
  status: RepositoryDependencyVulnerabilityObservation["status"],
  packagesInspected: ExactDependencyCoordinate[],
  findings: RepositoryDependencyVulnerabilityFinding[],
  maliciousPackageObservations: RepositoryDependencyVulnerabilityObservation["maliciousPackageObservations"],
  summary: RepositoryDependencyVulnerabilitySummary,
  cisaKev: RepositoryDependencyVulnerabilityObservation["cisaKev"],
  errors: string[],
  limitations: string[]
): RepositoryDependencyVulnerabilityObservation {
  const boundedErrors = boundedRepositoryOsvStrings(errors, MAX_REPOSITORY_OSV_ERROR_ENTRIES, "errors");
  const rawLimitations = [...limitations];
  if (boundedErrors.overflow) rawLimitations.push(`repository_osv_errors_truncated:${MAX_REPOSITORY_OSV_ERROR_ENTRIES}_of_${errors.length}`);
  if (boundedErrors.entryTruncated) rawLimitations.push("repository_osv_error_entry_truncated");
  const boundedLimitations = boundedRepositoryOsvStrings(rawLimitations, MAX_REPOSITORY_OSV_LIMITATION_ENTRIES, "limitations");
  return fitRepositoryDependencyVulnerabilityObservation({
    status,
    packagesInspected: [...packagesInspected].sort(compareCoordinates),
    findings: uniqueRepositoryVulnerabilityFindings(findings),
    maliciousPackageObservations: [...new Map(maliciousPackageObservations.map(item => [`${coordinateIdentity(item.coordinate)}:${item.id}`, item])).values()],
    summary,
    cisaKev,
    errors: boundedErrors.values,
    limitations: boundedLimitations.values
  });
}

async function collectRepositoryDependencyVulnerabilities(
  osv: OsvProvider,
  kev: CisaKevProvider,
  coordinates: ExactDependencyCoordinate[],
  deferred: number,
  selectedCount: number,
  resolutionIncomplete: boolean
): Promise<RepositoryDependencyVulnerabilityObservation> {
  const orderedCoordinates = [...coordinates].sort((left, right) => coordinateIdentity(left).localeCompare(coordinateIdentity(right)) || compareCoordinates(left, right));
  const limitations = deferred > 0 ? [`dependency_enrichment_limit_reached:${deferred}_of_${selectedCount}_deferred`] : [];
  if (resolutionIncomplete && orderedCoordinates.length === 0) {
    return finalizeRepositoryDependencyVulnerabilityObservation("NOT_CHECKED", [], [], [], repositoryVulnerabilitySummary("UNKNOWN", [], []), { status: "UNKNOWN", correlatableCveIds: [], matchedCveIds: [] }, [], limitations);
  }
  if (orderedCoordinates.length === 0) {
    return finalizeRepositoryDependencyVulnerabilityObservation("NOT_CHECKED", [], [], [], repositoryVulnerabilitySummary("NOT_CHECKED", [], []), { status: "NOT_QUERIED", correlatableCveIds: [], matchedCveIds: [] }, [], limitations);
  }

  const findings: RepositoryDependencyVulnerabilityFinding[] = [];
  const observedFindings: RepositoryDependencyVulnerabilityFinding[] = [];
  const maliciousPackageObservations: RepositoryDependencyVulnerabilityObservation["maliciousPackageObservations"] = [];
  const errors: string[] = [];
  let successfulQueries = 0;
  let failedQueries = 0;

  for (let offset = 0; offset < orderedCoordinates.length; offset += REPOSITORY_ENRICHMENT_CONCURRENCY) {
    const chunk = orderedCoordinates.slice(offset, offset + REPOSITORY_ENRICHMENT_CONCURRENCY);
    const results = await Promise.all(chunk.map(async coordinate => {
      const ecosystem = repositoryOsvEcosystem(coordinate.ecosystem);
      if (!ecosystem) return { coordinate, error: "unsupported_ecosystem" };
      try {
        return { coordinate, result: await osv.packageVulnerabilities(ecosystem, coordinate.name, coordinate.version) };
      } catch (error) {
        return { coordinate, error: error instanceof Error ? error.message : "unknown error" };
      }
    }));
    for (const item of results) {
      if ("error" in item) {
        failedQueries += 1;
        errors.push(`OSV ${repositoryOsvIdentity(item.coordinate)}: ${item.error}`);
        continue;
      }
      successfulQueries += 1;
      const packageFindings = item.result.findings.map(vulnerability => ({ coordinate: item.coordinate, vulnerability: { ...vulnerability, knownExploited: false, aliases: [...vulnerability.aliases].sort(compareText) }, sources: ["OSV"] as RepositoryDependencyVulnerabilityFinding["sources"] }));
      const uniquePackageFindings = uniqueRepositoryVulnerabilityFindings(packageFindings);
      observedFindings.push(...uniquePackageFindings);
      if (uniquePackageFindings.length > MAX_REPOSITORY_OSV_FINDINGS_PER_PACKAGE) limitations.push(`repository_osv_findings_truncated:${repositoryOsvIdentity(item.coordinate)}:${MAX_REPOSITORY_OSV_FINDINGS_PER_PACKAGE}_of_${uniquePackageFindings.length}`);
      findings.push(...uniquePackageFindings.slice(0, MAX_REPOSITORY_OSV_FINDINGS_PER_PACKAGE));
      for (const malicious of item.result.maliciousPackageObservations) {
        if (typeof malicious.id === "string" && malicious.id.length > 0) maliciousPackageObservations.push({ coordinate: item.coordinate, id: malicious.id, source: "OSV" });
      }
    }
  }

  const status = failedQueries === 0 ? "CHECKED" : successfulQueries === 0 ? "UNAVAILABLE" : "UNKNOWN";
  const uniqueFindings = uniqueRepositoryVulnerabilityFindings(observedFindings);
  if (uniqueFindings.length > MAX_REPOSITORY_OSV_FINDINGS_TOTAL) limitations.push(`repository_osv_total_findings_truncated:${MAX_REPOSITORY_OSV_FINDINGS_TOTAL}_of_${uniqueFindings.length}`);
  let retainedFindings = uniqueRepositoryVulnerabilityFindings(findings).slice(0, MAX_REPOSITORY_OSV_FINDINGS_TOTAL);
  const uniqueMalicious = [...new Map(maliciousPackageObservations.map(item => [`${coordinateIdentity(item.coordinate)}:${item.id}`, item])).values()]
    .sort((left, right) => compareCoordinates(left.coordinate, right.coordinate) || compareText(left.id, right.id));
  if (uniqueMalicious.length > MAX_REPOSITORY_OSV_MALICIOUS_OBSERVATIONS_TOTAL) limitations.push(`repository_osv_malicious_observations_truncated:${MAX_REPOSITORY_OSV_MALICIOUS_OBSERVATIONS_TOTAL}_of_${uniqueMalicious.length}`);
  const retainedMalicious = uniqueMalicious.slice(0, MAX_REPOSITORY_OSV_MALICIOUS_OBSERVATIONS_TOTAL);
  const completeOsv = status === "CHECKED" && !resolutionIncomplete && deferred === 0 && !limitations.some(item => item.startsWith("repository_osv_"));
  const correlatableCveIds = correlatableVulnerabilityIds(uniqueFindings.map(item => item.vulnerability));
  let cisaKev: RepositoryDependencyVulnerabilityObservation["cisaKev"] = {
    status: completeOsv && correlatableCveIds.length === 0 ? "NOT_QUERIED" : "UNKNOWN",
    correlatableCveIds,
    matchedCveIds: []
  };
  if (correlatableCveIds.length > 0 && successfulQueries > 0) {
    try {
      const observed = await kev.mark(correlatableCveIds);
      const matchedCveIds = correlatableCveIds.filter(id => observed.exploited.has(id));
      cisaKev = { status: "CHECKED", correlatableCveIds, matchedCveIds };
      const markKnownExploited = (finding: RepositoryDependencyVulnerabilityFinding): RepositoryDependencyVulnerabilityFinding => {
        const knownExploited = [finding.vulnerability.id, ...finding.vulnerability.aliases].some(id => observed.exploited.has(id));
        return { ...finding, vulnerability: { ...finding.vulnerability, knownExploited }, sources: [...new Set(["OSV", ...(knownExploited ? ["CISA KEV"] : [])])].sort(compareText) as RepositoryDependencyVulnerabilityFinding["sources"] };
      };
      const markedFindings = uniqueFindings.map(markKnownExploited);
      const markedByIdentity = new Map(markedFindings.map(finding => [vulnerabilityIdentity(finding), finding]));
      retainedFindings = retainedFindings.map(finding => markedByIdentity.get(vulnerabilityIdentity(finding)) ?? finding);
      const summaryStatus = successfulQueries === 0 ? "UNAVAILABLE" : limitations.some(item => item.startsWith("repository_osv_")) ? "TRUNCATED" : "VALID";
      return finalizeRepositoryDependencyVulnerabilityObservation(status, orderedCoordinates, retainedFindings, retainedMalicious, repositoryVulnerabilitySummary(summaryStatus, markedFindings, uniqueMalicious), cisaKev, errors, limitations);
    } catch (error) {
      cisaKev = { status: "UNAVAILABLE", correlatableCveIds, matchedCveIds: [] };
      errors.push(`CISA KEV: ${error instanceof Error ? error.message : "unknown error"}`);
    }
  }
  const summaryStatus = successfulQueries === 0 ? "UNAVAILABLE" : limitations.some(item => item.startsWith("repository_osv_")) ? "TRUNCATED" : "VALID";
  return finalizeRepositoryDependencyVulnerabilityObservation(status, orderedCoordinates, retainedFindings, retainedMalicious, repositoryVulnerabilitySummary(summaryStatus, uniqueFindings, uniqueMalicious), cisaKev, errors, limitations);
}

function truncateUtf8(value: unknown, maximumBytes: number): { value: string; truncated: boolean } {
  const text = typeof value === "string" ? value : "";
  const bytes = encoder.encode(text);
  if (bytes.byteLength <= maximumBytes) return { value: text, truncated: false };
  let end = maximumBytes;
  while (end > 0 && (bytes[end]! & 0xc0) === 0x80) end -= 1;
  return { value: decoder.decode(bytes.slice(0, end)), truncated: true };
}

function compareThreatFinding(left: RepositoryThreatIntelObservation["findings"][number], right: RepositoryThreatIntelObservation["findings"][number]): number {
  const severity = threatSeverityRank[right.finding.severity] - threatSeverityRank[left.finding.severity];
  if (severity !== 0) return severity;
  const coordinateResult = compareCoordinates(left.coordinate, right.coordinate);
  if (coordinateResult !== 0) return coordinateResult;
  const findingFields: Array<keyof ThreatFinding> = ["indicatorType", "indicator", "threatType", "source", "reference"];
  for (const field of findingFields) { const result = compareText(String(left.finding[field] ?? ""), String(right.finding[field] ?? "")); if (result !== 0) return result; }
  return 0;
}

function normalizeThreatFinding(coordinate: ExactDependencyCoordinate, finding: ThreatFinding): { value: RepositoryThreatIntelObservation["findings"][number]; truncated: boolean } {
  const indicator = truncateUtf8(finding.indicator, MAX_REPOSITORY_THREAT_INTEL_INDICATOR_BYTES);
  const threatType = truncateUtf8(finding.threatType, MAX_REPOSITORY_THREAT_INTEL_THREAT_TYPE_BYTES);
  const source = truncateUtf8(finding.source, MAX_REPOSITORY_THREAT_INTEL_SOURCE_BYTES);
  const reference = finding.reference === undefined ? undefined : truncateUtf8(finding.reference, MAX_REPOSITORY_THREAT_INTEL_REFERENCE_BYTES);
  return {
    value: { coordinate, finding: { indicatorType: finding.indicatorType, indicator: indicator.value, threatType: threatType.value, severity: finding.severity, source: source.value, ...(reference ? { reference: reference.value } : {}) } },
    truncated: indicator.truncated || threatType.truncated || source.truncated || Boolean(reference?.truncated)
  };
}

function uniqueSortedFindings(findings: RepositoryThreatIntelObservation["findings"]): RepositoryThreatIntelObservation["findings"] {
  const unique = new Map<string, RepositoryThreatIntelObservation["findings"][number]>();
  for (const finding of findings) {
    const key = JSON.stringify(finding);
    if (!unique.has(key)) unique.set(key, finding);
  }
  return [...unique.values()].sort(compareThreatFinding);
}

function boundedEntries(entries: string[], maximumEntries: number, label: "errors" | "limitations"): { values: string[]; overflow: boolean; entryTruncated: boolean } {
  let entryTruncated = false;
  const normalized = [...new Set(entries.map(entry => {
    const bounded = truncateUtf8(entry, MAX_REPOSITORY_THREAT_INTEL_ENTRY_BYTES);
    entryTruncated ||= bounded.truncated;
    return bounded.value;
  }))].sort(compareText);
  const overflow = normalized.length > maximumEntries;
  const marker = `threat_intel_${label}_truncated:${maximumEntries}_of_${normalized.length}`;
  const values = overflow ? [...normalized.slice(0, Math.max(0, maximumEntries - 1)), marker] : normalized;
  return { values: [...new Set(values)].sort(compareText), overflow, entryTruncated };
}

function isReservedLimitation(entry: string): boolean {
  return entry === "threat_intel_payload_truncated"
    || entry.startsWith("threat_intel_packages_inspected_truncated:")
    || entry.startsWith("threat_intel_errors_truncated:")
    || entry.startsWith("threat_intel_limitations_truncated:");
}

function boundedLimitations(entries: string[]): { values: string[]; entryTruncated: boolean } {
  let entryTruncated = false;
  const normalized = [...new Set(entries.map(entry => {
    const bounded = truncateUtf8(entry, MAX_REPOSITORY_THREAT_INTEL_ENTRY_BYTES);
    entryTruncated ||= bounded.truncated;
    return bounded.value;
  }))].sort(compareText);
  const mandatory = normalized.filter(isReservedLimitation);
  const ordinary = normalized.filter(entry => !isReservedLimitation(entry));
  const overflow = normalized.length > MAX_REPOSITORY_THREAT_INTEL_LIMITATION_ENTRIES;
  const existingOverflowMarker = normalized.find(entry => entry.startsWith("threat_intel_limitations_truncated:"));
  const overflowMarker = existingOverflowMarker ?? `threat_intel_limitations_truncated:${MAX_REPOSITORY_THREAT_INTEL_LIMITATION_ENTRIES}_of_${normalized.length}`;
  const reserved = [...new Set([...mandatory, ...(overflow && !existingOverflowMarker ? [overflowMarker] : [])])];
  const remaining = Math.max(0, MAX_REPOSITORY_THREAT_INTEL_LIMITATION_ENTRIES - reserved.length);
  return { values: [...new Set([...reserved, ...ordinary.slice(0, remaining)])].sort(compareText), entryTruncated };
}

function replaceLimitationMarker(entries: string[], prefix: string, marker: string): string[] {
  return [...entries.filter(entry => !entry.startsWith(prefix)), marker];
}

function fitRepositoryThreatIntelObservation(observation: RepositoryThreatIntelObservation): RepositoryThreatIntelObservation {
  const observedPackageCount = observation.packagesInspected.length;
  let packagesInspected = [...observation.packagesInspected].sort(compareCoordinates);
  let findings = [...observation.findings];
  let limitations = boundedLimitations(observation.limitations).values;
  let summary = observation.summary;
  const result = (): RepositoryThreatIntelObservation => ({ ...observation, ...(summary ? { summary } : {}), packagesInspected, findings, limitations });

  if (utf8Bytes(JSON.stringify(result())) <= MAX_REPOSITORY_THREAT_INTEL_BYTES) return result();

  limitations = boundedLimitations([...limitations, "threat_intel_payload_truncated"]).values;
  if (summary) summary = { ...summary, status: "TRUNCATED" };
  while (utf8Bytes(JSON.stringify(result())) > MAX_REPOSITORY_THREAT_INTEL_BYTES && findings.length > 0) findings.pop();
  while (utf8Bytes(JSON.stringify(result())) > MAX_REPOSITORY_THREAT_INTEL_BYTES && packagesInspected.length > 0) {
    packagesInspected.pop();
    limitations = boundedLimitations(replaceLimitationMarker(
      limitations,
      "threat_intel_packages_inspected_truncated:",
      `threat_intel_packages_inspected_truncated:${packagesInspected.length}_of_${observedPackageCount}`
    )).values;
  }

  if (utf8Bytes(JSON.stringify(result())) <= MAX_REPOSITORY_THREAT_INTEL_BYTES) return result();

  const diagnostic = "threat_intel_observation_reduction_failed";
  const fallbackLimitations = boundedLimitations([...limitations, diagnostic]).values;
  const fallback: RepositoryThreatIntelObservation = { ...result(), packagesInspected: [], findings: [], errors: [], limitations: fallbackLimitations };
  if (utf8Bytes(JSON.stringify(fallback)) <= MAX_REPOSITORY_THREAT_INTEL_BYTES) return fallback;

  return { ...result(), packagesInspected: [], findings: [], errors: [], limitations: [] };
}

function finalizeRepositoryThreatIntelObservation(status: RepositoryThreatIntelObservation["status"], packagesInspected: ExactDependencyCoordinate[], findings: RepositoryThreatIntelObservation["findings"], summary: RepositoryThreatIntelSummary, errors: string[], limitations: string[]): RepositoryThreatIntelObservation {
  const boundedErrors = boundedEntries(errors, MAX_REPOSITORY_THREAT_INTEL_ERROR_ENTRIES, "errors");
  const rawLimitations = [...limitations];
  if (boundedErrors.overflow) rawLimitations.push(`threat_intel_errors_truncated:${MAX_REPOSITORY_THREAT_INTEL_ERROR_ENTRIES}_of_${errors.length}`);
  if (boundedErrors.entryTruncated) rawLimitations.push("threat_intel_error_entry_truncated");
  if (rawLimitations.some(entry => utf8Bytes(entry) > MAX_REPOSITORY_THREAT_INTEL_ENTRY_BYTES)) rawLimitations.push("threat_intel_limitation_entry_truncated");
  const bounded = boundedLimitations(rawLimitations);
  return fitRepositoryThreatIntelObservation({ status, packagesInspected: [...packagesInspected], findings: uniqueSortedFindings(findings), summary, errors: boundedErrors.values, limitations: bounded.values });
}

export async function collectRepositoryThreatIntel(threatIntel: ThreatIntelStore, coordinates: ExactDependencyCoordinate[], deferred: number, selectedCount: number): Promise<RepositoryThreatIntelObservation> {
  if (coordinates.length === 0) return finalizeRepositoryThreatIntelObservation("NOT_CHECKED", [], [], repositoryThreatIntelSummary("NOT_CHECKED", []), [], ["no_exact_dependencies_selected"]);
  const observedFindings: RepositoryThreatIntelObservation["findings"] = [];
  const detailFindings: RepositoryThreatIntelObservation["findings"] = [];
  const errors: string[] = [];
  const limitations = deferred > 0 ? [`dependency_enrichment_limit_reached:${deferred}_of_${selectedCount}_deferred`] : [];
  let successfulLookups = 0;
  let unavailableLookups = 0;
  for (let offset = 0; offset < coordinates.length; offset += REPOSITORY_ENRICHMENT_CONCURRENCY) {
    const chunk = coordinates.slice(offset, offset + REPOSITORY_ENRICHMENT_CONCURRENCY);
    const results = await Promise.all(chunk.map(async coordinate => {
      try {
        return { coordinate, result: await threatIntel.lookupPackage(coordinate.ecosystem, coordinate.name, coordinate.version) };
      } catch (error) {
        return { coordinate, error: `${error instanceof Error ? error.message : "unknown error"}`.slice(0, 256) };
      }
    }));
    for (const item of results) {
      const identity = coordinateIdentity(item.coordinate);
      if ("error" in item) {
        unavailableLookups += 1;
        errors.push(`threat_intel ${identity}: ${item.error}`);
        limitations.push(`threat_intel_lookup_failed:${item.coordinate.name}@${item.coordinate.version}`);
        continue;
      }
      if (!item.result.checked) {
        unavailableLookups += 1;
        limitations.push(`threat_intel_unavailable:${item.coordinate.name}@${item.coordinate.version}`);
        continue;
      } else successfulLookups += 1;
      const normalized: RepositoryThreatIntelObservation["findings"] = [];
      let fieldTruncated = false;
      for (const finding of Array.isArray(item.result.findings) ? item.result.findings : []) {
        const bounded = normalizeThreatFinding(item.coordinate, finding);
        normalized.push(bounded.value);
        fieldTruncated ||= bounded.truncated;
      }
      const unique = uniqueSortedFindings(normalized);
      observedFindings.push(...unique);
      if (fieldTruncated) limitations.push(`threat_intel_finding_field_truncated:${identity}`);
      if (unique.length > MAX_REPOSITORY_THREAT_FINDINGS_PER_PACKAGE) {
        limitations.push(`threat_intel_findings_truncated:${identity}:${MAX_REPOSITORY_THREAT_FINDINGS_PER_PACKAGE}_of_${unique.length}`);
      }
      detailFindings.push(...unique.slice(0, MAX_REPOSITORY_THREAT_FINDINGS_PER_PACKAGE));
    }
  }
  const allFindings = uniqueSortedFindings(observedFindings);
  if (allFindings.length > MAX_REPOSITORY_THREAT_FINDINGS_TOTAL) limitations.push(`threat_intel_total_findings_truncated:${MAX_REPOSITORY_THREAT_FINDINGS_TOTAL}_of_${allFindings.length}`);
  const retained = uniqueSortedFindings(detailFindings).slice(0, MAX_REPOSITORY_THREAT_FINDINGS_TOTAL);
  const status = unavailableLookups === 0 ? "CHECKED" : successfulLookups === 0 ? "UNAVAILABLE" : "UNKNOWN";
  const summaryStatus = successfulLookups === 0 ? "UNAVAILABLE" : limitations.some(threatIntelDetailWasTruncated) ? "TRUNCATED" : "VALID";
  return finalizeRepositoryThreatIntelObservation(status, coordinates, retained, repositoryThreatIntelSummary(summaryStatus, allFindings), errors, limitations);
}

function repositoryThreatIntelDetail(observation: RepositoryThreatIntelObservation): Record<string, unknown> {
  return { status: observation.status, packagesInspected: observation.packagesInspected, findings: observation.findings, summary: observation.summary, errors: observation.errors, limitations: observation.limitations };
}

function repositoryDependencyVulnerabilityDetail(observation: RepositoryDependencyVulnerabilityObservation): Record<string, unknown> {
  return { status: observation.status, packagesInspected: observation.packagesInspected, findings: observation.findings, maliciousPackageObservations: observation.maliciousPackageObservations, summary: observation.summary, cisaKev: observation.cisaKev, errors: observation.errors, limitations: observation.limitations };
}


export class OmniIntelligence {
  constructor(
    private readonly engine: RiskEngine,
    private readonly cache: CachedLoader,
    private readonly osv: OsvProvider,
    private readonly kev: CisaKevProvider,
    private readonly scorecard: ScorecardProvider,
    private readonly npm: NpmRegistryProvider,
    private readonly circle: CircleDiscoveryProvider,
    private readonly probe: X402Probe,
    private readonly history: HistoryStore,
    private readonly threatIntel: ThreatIntelStore,
    private readonly journal: AssessmentJournal = new NoopAssessmentJournal(),
    private readonly github: GitHubRepositoryProvider = {} as GitHubRepositoryProvider,
    private readonly depsDev: DepsDevProvider = {} as DepsDevProvider,
    private readonly agentReputationPolicy: AgentReputationPolicy = DEFAULT_AGENT_REPUTATION_POLICY,
    private readonly agentProvider: AgentRiskProvider = DEFAULT_AGENT_RISK_PROVIDER
  ) {}

  private async assessAndJournal(snapshot: RiskSnapshot): Promise<RiskAssessment> {
    const features = extractRiskFeatures(snapshot);
    const assessment = this.engine.assessFeatures(snapshot, features);
    try {
      await this.journal.record(snapshot, features, assessment);
    } catch (error) {
      console.error(JSON.stringify({ level: "error", event: "assessment_journal_write_failed", message: error instanceof Error ? error.message : "unknown error" }));
    }
    return assessment;
  }

  async packageRisk(ecosystem: string, name: string, version: string): Promise<RiskAssessment> {
    const key = `assessment:package:${RISK_POLICY_VERSION}:${PACKAGE_COVERAGE_MODEL_VERSION}:${[ecosystem, name, version].map(cachePart).join(":")}`;
    return this.cache.getOrLoad(key, 300, async () => {
      const errors: string[] = [];
      let vulnerabilities: RiskSnapshot["vulnerabilities"];
      let exploitationChecked = false;
      let packageSupplyChain: RiskSnapshot["packageSupplyChain"];
      let maliciousPackageObservations: RiskSnapshot["maliciousPackageObservations"] = [];
      let threatIntelChecked = false;
      let threatFindings: ThreatFinding[] = [];
      const coverageSources: EvidenceCoverageSource[] = [];
      const evidence: RiskSnapshot["evidence"] = [];

      try {
        const osv = await this.osv.packageVulnerabilities(ecosystem, name, version);
        vulnerabilities = osv.findings;
        maliciousPackageObservations = osv.maliciousPackageObservations ?? [];
        evidence.push(...osv.evidence);
        coverageSources.push(coverageSource("OSV", "QUERIED", vulnerabilities.length > 0 ? "OBSERVED" : "ABSENT"));
        if (vulnerabilities.length > 0) {
          const kevIds = correlatableVulnerabilityIds(vulnerabilities);
          if (kevIds.length === 0) {
            exploitationChecked = true;
            coverageSources.push(coverageSource("CISA KEV", "NOT_QUERIED", "NOT_APPLICABLE"));
          } else {
            try {
              const kev = await this.kev.mark(kevIds);
              for (const vuln of vulnerabilities) {
                vuln.knownExploited = kev.exploited.has(vuln.id) || vuln.aliases.some(alias => kev.exploited.has(alias));
              }
              exploitationChecked = true;
              coverageSources.push(coverageSource("CISA KEV", "QUERIED", kev.exploited.size > 0 ? "OBSERVED" : "ABSENT"));
              evidence.push(kev.evidence);
            } catch (error) {
              coverageSources.push(coverageSource("CISA KEV", "QUERIED", "UNAVAILABLE"));
              errors.push(`CISA KEV: ${error instanceof Error ? error.message : "unknown error"}`);
            }
          }
        } else {
          exploitationChecked = true;
          coverageSources.push(coverageSource("CISA KEV", "NOT_QUERIED", "NOT_APPLICABLE"));
        }
      } catch (error) {
        coverageSources.push(coverageSource("OSV", "QUERIED", "UNAVAILABLE"));
        coverageSources.push(coverageSource("CISA KEV", "NOT_QUERIED", "UNKNOWN"));
        errors.push(`OSV: ${error instanceof Error ? error.message : "unknown error"}`);
      }

      if (ecosystem.toLowerCase() === "npm") {
        try {
          const registry = await this.npm.packageMetadata(name, version);
          packageSupplyChain = registry.signals;
          evidence.push(registry.evidence);
          coverageSources.push(coverageSource("npm Registry", "QUERIED", "OBSERVED"));
        } catch (error) {
          coverageSources.push(coverageSource("npm Registry", "QUERIED", "UNAVAILABLE"));
          errors.push(`npm Registry: ${error instanceof Error ? error.message : "unknown error"}`);
        }
      } else {
        coverageSources.push(coverageSource("npm Registry", "NOT_QUERIED", "NOT_APPLICABLE"));
      }

      try {
        const threat = await this.threatIntel.lookupPackage(ecosystem, name, version);
        threatIntelChecked = threat.checked;
        threatFindings = threat.findings;
        if (!threat.checked) {
          coverageSources.push(coverageSource("Threat Intelligence", "QUERIED", "UNAVAILABLE"));
          errors.push("Threat intelligence: no licensed feed loaded");
        } else {
          coverageSources.push(coverageSource("Threat Intelligence", "QUERIED", threat.findings.length > 0 ? "OBSERVED" : "ABSENT"));
          evidence.push({ source: "OMNI threat intelligence", kind: "package_ioc_lookup", observedAt: new Date().toISOString(), detail: { matches: threat.findings.length } });
        }
      } catch (error) {
        coverageSources.push(coverageSource("Threat Intelligence", "QUERIED", "UNAVAILABLE"));
        errors.push(`Threat intelligence: ${error instanceof Error ? error.message : "unknown error"}`);
      }

      return this.assessAndJournal({
        subject: { type: "package", id: `${ecosystem}:${name}@${version}` },
        ...(vulnerabilities === undefined ? {} : { vulnerabilities }), exploitationChecked,
        ...(packageSupplyChain ? { packageSupplyChain } : {}),
        ...(maliciousPackageObservations.length > 0 ? { maliciousPackageObservations } : {}),
        threatIntelChecked, threatFindings,
        coverage: { modelVersion: PACKAGE_COVERAGE_MODEL_VERSION, sources: coverageSources },
        evidence, sourceErrors: errors
      });
    });
  }

  async repositoryRisk(owner: string, repo: string): Promise<RiskAssessment> {
    const target = `github.com/${owner}/${repo}`;
    let canonicalRepository: string | undefined;
    try {
      const identity = await this.github.resolve(owner, repo);
      canonicalRepository = identity.repository;
      return await this.cache.getOrLoad(`assessment:repo:${RISK_POLICY_VERSION}:${REPOSITORY_COVERAGE_MODEL_VERSION}:${identity.repository}:${identity.resolvedCommitSha}`, REPOSITORY_ASSESSMENT_CACHE_TTL_SECONDS, async () => {
        const repositoryEvidence = await this.github.collectResolved(owner, repo, identity);
        return this.repositoryRiskFromEvidence(repositoryEvidence);
      });
    }
    catch (error) {
      const repositoryError = `GitHub: ${error instanceof Error ? error.message : "unknown error"}`;
      const repositoryEvidence: RepositoryEvidence = { target: { repository: canonicalRepository ?? target }, githubCollection: { status: "partial", limitations: ["github_collection_unavailable"], sourceErrors: [repositoryError] }, securityFiles: [], dependencies: { exact: [], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } }, dependencyObservations: [], dependencyVulnerabilities: { status: "NOT_CHECKED", packagesInspected: [], findings: [], maliciousPackageObservations: [], cisaKev: { status: "UNKNOWN", correlatableCveIds: [], matchedCveIds: [] }, errors: [], limitations: ["github_collection_unavailable"] }, dependencyThreatIntel: { status: "NOT_CHECKED", packagesInspected: [], findings: [], errors: [], limitations: ["github_collection_unavailable"] }, coverage: { status: "partial", treeEntriesInspected: 0, filesInspected: 0, bytesInspected: 0, limitations: ["github_collection_unavailable"] }, sourceErrors: [repositoryError] };
      return this.repositoryRiskFromEvidence(repositoryEvidence);
    }
  }

  private async repositoryRiskFromEvidence(repositoryEvidence: RepositoryEvidence): Promise<RiskAssessment> {
    const githubCollection = repositoryEvidence.githubCollection ?? githubCollectionFallback(repositoryEvidence);
    const evidence: RiskSnapshot["evidence"] = [{ source: "GitHub", kind: "repository_primary_evidence", observedAt: new Date().toISOString(), detail: { repository: repositoryEvidence.target.repository, ...(repositoryEvidence.target.resolvedCommitSha ? { resolvedCommitSha: repositoryEvidence.target.resolvedCommitSha } : {}), coverage: githubCollection.status, limitations: githubCollection.limitations } }];
    const sourceErrors: string[] = []; let scorecard: number | undefined;
    const scorecardIdentity = { repository: repositoryEvidence.target.repository, ...(repositoryEvidence.target.resolvedCommitSha ? { resolvedCommitSha: repositoryEvidence.target.resolvedCommitSha } : {}) };
    const scorecardResult = await this.scorecard.repository(scorecardIdentity, "latest");
    if (scorecardResult.status === "available") { scorecard = scorecardResult.score; evidence.push(scorecardResult.evidence); }
    else {
      const detail = scorecardResult.diagnostic;
      const status = detail.httpStatus === undefined ? "" : ` HTTP ${detail.httpStatus}`;
      sourceErrors.push(`OpenSSF Scorecard: ${scorecardResult.status} (${detail.reason};${status} ${detail.host}; mode=${detail.mode}; repository=${detail.repository})`);
    }
    // Deterministic order and upstream deduplication bound the deps.dev fan-out:
    // one enrichment per distinct package@version regardless of how many workspaces
    // declare it. Overflow is never silently discarded — it stays visible as a
    // partial-coverage limitation with the exact deferred count.
    const allCoordinates = [...repositoryEvidence.dependencies.exact].sort((a, b) => a.ecosystem.localeCompare(b.ecosystem) || a.name.localeCompare(b.name) || a.version.localeCompare(b.version) || a.manifestPath.localeCompare(b.manifestPath) || a.workspacePath.localeCompare(b.workspacePath));
    const deduped = new Map<string, ExactDependencyCoordinate>();
    for (const coordinate of allCoordinates) if (!deduped.has(coordinateIdentity(coordinate))) deduped.set(coordinateIdentity(coordinate), coordinate);
    const selected = [...deduped.values()];
    const enriched = selected.slice(0, REPOSITORY_DEPENDENCY_ENRICHMENT_LIMIT);
    const deferred = selected.length - enriched.length;
    if (deferred > 0) {
      repositoryEvidence.coverage.status = "partial";
      repositoryEvidence.coverage.limitations.push(`dependency_enrichment_limit_reached:${deferred}_of_${selected.length}_deferred`);
    }
    const dependencyResolution = repositoryDependencyResolutionCoverage(repositoryEvidence, githubCollection);
    const resolutionIncomplete = dependencyResolution.status === "UNKNOWN";
    const vulnerabilityObservation = await collectRepositoryDependencyVulnerabilities(this.osv, this.kev, enriched, deferred, selected.length, resolutionIncomplete);
    repositoryEvidence.dependencyVulnerabilities = vulnerabilityObservation;
    evidence.push({ source: "OSV", kind: "repository_dependency_vulnerabilities", observedAt: new Date().toISOString(), detail: repositoryDependencyVulnerabilityDetail(vulnerabilityObservation) });
    if (vulnerabilityObservation.cisaKev.status !== "NOT_QUERIED") {
      evidence.push({ source: "CISA KEV", kind: "repository_dependency_known_exploitation", observedAt: new Date().toISOString(), detail: { ...vulnerabilityObservation.cisaKev } });
    }
    const threatIntelObservation = await collectRepositoryThreatIntel(this.threatIntel, enriched, deferred, selected.length);
    repositoryEvidence.dependencyThreatIntel = threatIntelObservation;
    evidence.push({ source: "OMNI threat intelligence", kind: "repository_dependency_ioc_lookup", observedAt: new Date().toISOString(), detail: repositoryThreatIntelDetail(threatIntelObservation) });
    for (let offset = 0; offset < enriched.length; offset += REPOSITORY_ENRICHMENT_CONCURRENCY) {
      const chunk = enriched.slice(offset, offset + REPOSITORY_ENRICHMENT_CONCURRENCY);
      await Promise.all(chunk.map(async coordinate => {
        try {
          const observed = await this.depsDev.packageVersion(coordinate);
          repositoryEvidence.dependencyObservations.push(observed.observation);
          repositoryEvidence.dependencies.resolvedGraph.packagesChecked += 1;
          repositoryEvidence.dependencies.resolvedGraph.nodesObserved += observed.observation.graph.nodeCount;
          if (!observed.observation.graph.checked && observed.observation.graph.error) {
            repositoryEvidence.dependencies.resolvedGraph.errors.push(`deps.dev graph ${coordinate.name}@${coordinate.version}: ${observed.observation.graph.error}`);
            repositoryEvidence.coverage.status = "partial";
            repositoryEvidence.coverage.limitations.push(`deps_dev_graph_unavailable:${coordinate.name}@${coordinate.version}`);
          }
          evidence.push(observed.evidence);
        }
        catch (error) { repositoryEvidence.sourceErrors.push(`deps.dev ${coordinate.name}@${coordinate.version}: ${error instanceof Error ? error.message : "unknown error"}`); repositoryEvidence.coverage.status = "partial"; repositoryEvidence.coverage.limitations.push(`deps_dev_unavailable:${coordinate.name}@${coordinate.version}`); }
      }));
    }
    evidence[0]!.detail.collectorErrors = [...githubCollection.sourceErrors];
    evidence[0]!.detail.coverage = githubCollection.status;
    evidence[0]!.detail.limitations = [...new Set(githubCollection.limitations)].sort();
    sourceErrors.push(...repositoryEvidence.sourceErrors);
    const coverageSources = repositoryCoverage(repositoryEvidence, scorecardResult, enriched.length, deferred, githubCollection);
    return this.assessAndJournal({ subject: { type: "repository", id: repositoryEvidence.target.repository }, ...(scorecard === undefined ? {} : { scorecard }), repositoryEvidence, coverage: { modelVersion: REPOSITORY_COVERAGE_MODEL_VERSION, sources: coverageSources }, evidence, sourceErrors });
  }

  async dependenciesRisk(packages: Array<{ ecosystem: string; name: string; version: string }>) {
    const assessments: RiskAssessment[] = [];
    for (let offset = 0; offset < packages.length; offset += 16) {
      const chunk = packages.slice(offset, offset + 16);
      assessments.push(...await Promise.all(chunk.map(p => this.packageRisk(p.ecosystem, p.name, p.version))));
    }
    const worst = assessments.reduce((max, item) => Math.max(max, item.riskScore), 0);
    const counts = assessments.reduce<Record<string, number>>((acc, item) => { acc[item.recommendation] = (acc[item.recommendation] ?? 0) + 1; return acc; }, {});
    return { packages: assessments, summary: { count: assessments.length, worstRiskScore: worst, recommendations: counts }, assessedAt: new Date().toISOString() };
  }

  async endpointPreflight(resource: string): Promise<X402EndpointPreflight> {
    return (async () => {
      const errors: string[] = [];
      const evidence: RiskSnapshot["evidence"] = [];
      let listedOnCircle: boolean | undefined, supportsGateway: boolean | undefined, supportsVanilla: boolean | undefined;
      let responseStatus: number | undefined, paymentOptions: number | undefined, listedMethod: string | undefined;
      let payTo: string | undefined, network: string | undefined, priceAtomic: string | undefined;
      let activeProbeChecked = false, historyChecked = false, threatIntelChecked = false;
      let endpointHistory: RiskSnapshot["endpointHistory"];
      let threatFindings: ThreatFinding[] = [];
      let observedPaymentRequirements: ObservedPaymentRequirement[] = [];

      try {
        const listing = await this.circle.findExact(resource);
        evidence.push(listing.evidence);
        listedOnCircle = listing.item !== undefined;
        if (listing.item) {
          listedMethod = listing.item.metadata?.method?.toUpperCase();
          supportsGateway = listing.item.metadata?.supportsCircleGateway;
          supportsVanilla = listing.item.metadata?.supportsVanillax402;
          payTo = listing.observation?.payTo;
          network = listing.observation?.network;
          priceAtomic = listing.observation?.priceAtomic;
          observedPaymentRequirements = listing.paymentOptions;
          if (listing.observation) {
            try {
              await this.history.recordEndpoint(listing.observation);
            } catch (error) {
              errors.push(`OMNI history: current Circle observation could not be recorded: ${error instanceof Error ? error.message : "unknown error"}`);
            }
          }
        }
      } catch (error) { errors.push(`Circle Discovery: ${error instanceof Error ? error.message : "unknown error"}`); }

      if (listedMethod === undefined || listedMethod === "GET") {
        try {
          const probe = await this.probe.unpaidGet(resource);
          activeProbeChecked = true; responseStatus = probe.status; paymentOptions = probe.paymentOptions.length; observedPaymentRequirements = probe.paymentOptions; evidence.push(probe.evidence);
        } catch (error) { errors.push(`Active probe: ${error instanceof Error ? error.message : "unknown error"}`); }
      } else {
        activeProbeChecked = true;
        evidence.push({ source: "OMNI active probe", kind: "probe_skipped", observedAt: new Date().toISOString(), detail: { resource, reason: "non_get_method", method: listedMethod } });
      }

      try {
        endpointHistory = await this.history.endpointHistory(resource, payTo);
        historyChecked = endpointHistory !== undefined;
        if (!historyChecked) errors.push("OMNI history: database not configured");
        else evidence.push({ source: "OMNI history", kind: "endpoint_change_history", observedAt: new Date().toISOString(), detail: endpointHistory as unknown as Record<string, unknown> });
      } catch (error) { errors.push(`OMNI history: ${error instanceof Error ? error.message : "unknown error"}`); }

      try {
        const threat = await this.threatIntel.lookupEndpoint(resource, payTo);
        threatIntelChecked = threat.checked; threatFindings = threat.findings;
        if (!threat.checked) errors.push("Threat intelligence: no licensed feed loaded");
        else evidence.push({ source: "OMNI threat intelligence", kind: "endpoint_ioc_lookup", observedAt: new Date().toISOString(), detail: { matches: threat.findings.length, checkedWallet: Boolean(payTo) } });
      } catch (error) { errors.push(`Threat intelligence: ${error instanceof Error ? error.message : "unknown error"}`); }

      return {
        ...await this.assessAndJournal({
          subject: { type: "x402_endpoint", id: resource },
          endpoint: { ...(listedOnCircle === undefined ? {} : { listedOnCircle }), ...(supportsGateway === undefined ? {} : { supportsGateway }), ...(supportsVanilla === undefined ? {} : { supportsVanilla }), ...(responseStatus === undefined ? {} : { responseStatus }), ...(paymentOptions === undefined ? {} : { paymentOptions }), ...(payTo ? { payTo } : {}), ...(network ? { network } : {}), ...(priceAtomic ? { priceAtomic } : {}) },
          activeProbeChecked, historyChecked, ...(endpointHistory ? { endpointHistory } : {}), threatIntelChecked, threatFindings,
          evidence, sourceErrors: errors
        }),
        preflightContext: {
          resource,
          paymentOptions: observedPaymentRequirements
        }
      };
    })();
  }

  /**
   * Assesses an ERC-8004 registered agent by agentId.
   * @param agentId - The ERC-721 token id (decimal string) in the IdentityRegistry.
   * @param chainRef - CAIP-2 chain reference (e.g. "eip155:1"). REQUIRED.
   * @param targetUrl - Optional caller-supplied target URL. If advertised in the
   *                    agent's verified card, a redirect-to-private probe is run.
   * @param trustedReviewers - Operator-configured allowlist for on-chain feedback
   *                           (lowercase addresses). Default null = public feedback
   *                           treated as evidence-only (not trust score input).
   * @param reputationMaxChunkAttempts - Maximum eth_getLogs chunk attempts per chain.
   */
  async agentRisk(
    agentId: string,
    chainRef: string = "eip155:1",
    targetUrl?: string,
    trustedReviewers: Set<string> | null = null,
    reputationMaxChunkAttempts = REPUTATION_DEFAULT_MAX_CHUNKS,
  ): Promise<AgentRiskAssessment> {
    // Resolve chain config
    const chain = getChainConfig(chainRef);
    if (!chain) {
      const agentRisk: AgentRisk = {
        agentId,
        primaryChainId: 0,
        dimensions: { agentIdentity: "unknown", agentReputation: "unknown", agentValidation: "unknown" },
        chainEvidence: [],
        policyVersion: "omni-agent-risk-v1",
        coverageVersion: AGENT_COVERAGE_MODEL_VERSION,
      };
      const baseAssessment = await this.assessAndJournal({
        subject: { type: "agent", id: `eip155:0:unknown:${agentId}` },
        coverage: { modelVersion: AGENT_COVERAGE_MODEL_VERSION, sources: [coverageSource("ERC-8004 Identity Registry", "NOT_QUERIED", "UNKNOWN")] },
        evidence: [],
        sourceErrors: [`unsupported chain: ${chainRef}`],
      });
      return { ...baseAssessment, agentRisk };
    }

    // Canonical subject ID: eip155:<chainId>:<identityRegistry>:<agentId>
    const canonicalId = `${chainRef}:${chain.identityRegistry}:${agentId}`;

    const observedAt = new Date().toISOString();
    const errors: string[] = [];
    const evidence: RiskSnapshot["evidence"] = [];
    const coverageSources: EvidenceCoverageSource[] = [];

    // Parse agentId: decimal only (hex rejected at validation layer)
    let agentIdBigInt: bigint;
    try {
      agentIdBigInt = BigInt(agentId);
      if (agentIdBigInt < 0n) throw new Error("agentId must be non-negative");
    } catch {
      const agentRisk: AgentRisk = {
        agentId,
        primaryChainId: chain.chainId,
        dimensions: { agentIdentity: "unknown", agentReputation: "unknown", agentValidation: "unknown" },
        chainEvidence: [],
        policyVersion: "omni-agent-risk-v1",
        coverageVersion: AGENT_COVERAGE_MODEL_VERSION,
      };
      const baseAssessment = await this.assessAndJournal({
        subject: { type: "agent", id: canonicalId },
        coverage: { modelVersion: AGENT_COVERAGE_MODEL_VERSION, sources: [coverageSource("ERC-8004 Identity Registry", "NOT_QUERIED", "UNKNOWN")] },
        evidence: [],
        sourceErrors: [`invalid agentId: ${agentId}`],
      });
      return { ...baseAssessment, agentRisk };
    }

    // --- Phase 1: Identity on specified chain ---
    const chains: readonly Erc8004ChainConfig[] = [chain];
    const chainResults: AgentChainIdentityResult[] = await Promise.all(
      chains.map(async c => {
        try {
          return await this.agentProvider.readAgentIdentity(c, agentIdBigInt);
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          return { chainId: c.chainId, registered: false, status: "UNAVAILABLE" as const, ownerAddress: undefined, agentWallet: undefined, registrationUri: undefined, error: msg };
        }
      })
    );

    const registeredResults = chainResults.filter(r => r.status === "REGISTERED");
    const isRegistered = registeredResults.length > 0;
    const identityProbeStatus: AgentChainIdentityResult["status"] = isRegistered
      ? "REGISTERED"
      : chainResults.some(result => result.status === "UNAVAILABLE")
        ? "UNAVAILABLE"
        : "NOT_REGISTERED";

    // Classify identity errors
    const identityErrors = chainResults.filter(r => r.error);
    const identityExecution: EvidenceCoverageSource["execution"] = "QUERIED";
    const identityCoverageStatus: EvidenceCoverageSource["status"] =
      identityProbeStatus === "REGISTERED" ? "OBSERVED"
      : identityProbeStatus === "UNAVAILABLE" ? "UNAVAILABLE"
      : "ABSENT";
    coverageSources.push(coverageSource("ERC-8004 Identity Registry", identityExecution, identityCoverageStatus));
    for (const r of identityErrors) {
      errors.push(`ERC-8004 identity chain ${r.chainId}: ${r.error ?? "unknown error"}`);
    }

    // Track identity evidence for scoring
    evidence.push({
      source: "ERC-8004 IdentityRegistry",
      kind: "agent_identity",
      observedAt,
      detail: {
        agentId,
        status: identityProbeStatus,
        registered: isRegistered,
        chainRef,
        chains: chainResults.map(r => ({
          chainId: r.chainId,
          status: r.status,
          registered: r.registered,
          ...(r.ownerAddress ? { ownerAddress: r.ownerAddress } : {}),
          ...(r.agentWallet ? { agentWallet: r.agentWallet } : {}),
          ...(r.registrationUri ? { registrationUri: r.registrationUri } : {}),
          ...(r.error ? { error: r.error } : {}),
        })),
      },
    });

    // Pick the primary registration (first registered chain, or first chain overall).
    const primary = registeredResults[0] ?? chainResults[0];
    const primaryChainId = primary?.chainId ?? chain.chainId;
    const primaryAgentWallet = primary?.agentWallet;
    const primaryRegistrationUri = primary?.registrationUri;

    // --- Phase 2: Agent card fetch (if registered and URI available) ---
    let agentName: string | undefined;
    let agentDescription: string | undefined;
    let services: AgentRisk["services"];
    let agentValidation: AgentRisk["dimensions"]["agentValidation"] = "unknown";
    let cardUnavailable = false;
    let registrationMismatch = false;
    let cardVerified = false;

    if (isRegistered && primaryRegistrationUri) {
      try {
        const cardResult = await this.agentProvider.fetchAgentCard(primaryRegistrationUri, {
          agentRegistry: `eip155:${primary.chainId}:${chain.identityRegistry}`,
          agentId: agentIdBigInt,
        });
        if (cardResult.status === "SELF_REFERENCE_MISMATCH") {
          registrationMismatch = true;
          agentValidation = "unknown";
          evidence.push({ source: "ERC-8004 Agent Card", kind: "agent_registration_mismatch", observedAt, detail: { reason: "self_reference_mismatch", registrationUri: primaryRegistrationUri } });
          coverageSources.push(coverageSource("ERC-8004 Agent Card", "QUERIED", "ABSENT"));
        } else if (cardResult.error) {
          errors.push(`agent card: ${cardResult.error}`);
          agentValidation = "card_unavailable";
          cardUnavailable = true;
          coverageSources.push(coverageSource("ERC-8004 Agent Card", "QUERIED", "UNAVAILABLE"));
          evidence.push({
            source: "ERC-8004 Agent Card",
            kind: "agent_card_unavailable",
            observedAt,
            detail: { registrationUri: primaryRegistrationUri, error: cardResult.error },
          });
        } else if (cardResult.card && cardResult.status === "SELF_REFERENCE_MATCH") {
          const card = cardResult.card;
          cardVerified = true;
          if (typeof card.name === "string") agentName = card.name.slice(0, 256);
          if (typeof card.description === "string") agentDescription = card.description.slice(0, 1024);
          services = extractServices(card);
          agentValidation = services.length > 0 ? "services_observed" : "no_services";
          coverageSources.push(coverageSource("ERC-8004 Agent Card", "QUERIED", services.length > 0 ? "OBSERVED" : "ABSENT"));
          evidence.push({
            source: "ERC-8004 Agent Card",
            kind: "agent_card",
            observedAt,
            detail: {
              registrationUri: primaryRegistrationUri,
              name: agentName ?? null,
              serviceCount: services.length,
              active: card.active,
            },
          });
          // Check registration match

        } else {
          agentValidation = "card_unavailable";
          cardUnavailable = true;
          coverageSources.push(coverageSource("ERC-8004 Agent Card", "QUERIED", "UNAVAILABLE"));
        }
      } catch (e) {
        errors.push(`agent card fetch: ${e instanceof Error ? e.message : String(e)}`);
        agentValidation = "card_unavailable";
        cardUnavailable = true;
        coverageSources.push(coverageSource("ERC-8004 Agent Card", "QUERIED", "UNAVAILABLE"));
      }
    } else if (isRegistered) {
      agentValidation = "card_unavailable";
      cardUnavailable = true;
      coverageSources.push(coverageSource("ERC-8004 Agent Card", "NOT_QUERIED", "NOT_APPLICABLE"));
    } else {
      agentValidation = "unknown";
      coverageSources.push(coverageSource("ERC-8004 Agent Card", "NOT_QUERIED", "NOT_APPLICABLE"));
    }

    // --- Phase 3: Reputation scan (only if registered) ---
    let reputationSummary: AgentReputationSummary | undefined;
    let agentReputation: AgentRisk["dimensions"]["agentReputation"] = "unknown";
    let trustedFeedbackExists = false;
    let strongestTrustedRisk: number | undefined;

    if (isRegistered && primary) {
      const primaryChain = chains.find(c => c.chainId === primary.chainId) ?? chain;
      if (primaryChain) {
        try {
          const configuredReviewers = trustedReviewers ?? this.agentReputationPolicy.trustedReviewers;
          const scan = await this.agentProvider.scanAgentReputation(primaryChain, agentIdBigInt, configuredReviewers, reputationMaxChunkAttempts);
          const active = scan.feedback.filter(f => !f.revoked);
          const uniqueReviewers = new Set(scan.feedback.map(f => f.clientAddress)).size;

          let recognizedTags = 0;
          let unrecognizedTags = 0;
          let validDecimalsFeedback = 0;
          let maxRiskFromTrusted = 0;
          let scoreEligibleFeedback = 0;

          for (const fb of active) {
            const policy = this.agentReputationPolicy.recognizedTags.find(item => item.tag === fb.tag1);
            if (policy) {
              recognizedTags++;
              const decimalsAllowed = policy.expectedDecimals === undefined
                ? policy.allowedDecimals === undefined || policy.allowedDecimals.includes(fb.valueDecimals)
                : fb.valueDecimals === policy.expectedDecimals;
              const reviewerTrusted = configuredReviewers.has(fb.clientAddress.toLowerCase());
              if (decimalsAllowed && fb.valueDecimals <= 18) validDecimalsFeedback++;
              if (decimalsAllowed && reviewerTrusted && decimalParts(policy.threshold) && fb.valueDecimals <= 18) {
                scoreEligibleFeedback++;
                const riskScore = thresholdBreached(fb.value, fb.valueDecimals, policy) ? policy.riskWeight : 0;
                maxRiskFromTrusted = Math.max(maxRiskFromTrusted, riskScore);
              }
            } else {
              unrecognizedTags++;
            }
          }

          trustedFeedbackExists = scoreEligibleFeedback > 0;
          strongestTrustedRisk = trustedFeedbackExists ? maxRiskFromTrusted : undefined;

          reputationSummary = {
            chainId: primary.chainId,
            totalFeedback: scan.feedback.length,
            activeFeedback: active.length,
            revokedFeedback: scan.feedback.filter(f => f.revoked).length,
            uniqueReviewers,
            recognizedTags,
            unrecognizedTags,
            validDecimalsFeedback,
            scoreEligibleFeedback,
            historyCoverage: scan.historyCoverage,
            blocksScanned: scan.blocksScanned.toString(10),
            errors: scan.errors,
          };
          for (const e of scan.errors) errors.push(`reputation scan: ${e}`);

          // Derive agentReputation dimension
          if (active.length === 0) {
            agentReputation = "insufficient";
          } else if (recognizedTags === 0) {
            // No recognized tags — feedback is evidence only, no score effect
            agentReputation = "insufficient";
          } else if (scoreEligibleFeedback === 0) {
            // Recognized public feedback without score-eligible trusted entries is not positive evidence.
            agentReputation = "insufficient";
          } else if (maxRiskFromTrusted >= 60) {
            agentReputation = "negative";
          } else if (maxRiskFromTrusted > 0) {
            agentReputation = "neutral";
          } else {
            agentReputation = "positive";
          }

          const reputationEvidenceStatus: EvidenceCoverageSource["status"] =
            active.length > 0
              ? scan.historyCoverage === "complete" ? "OBSERVED" : "UNKNOWN"
              : "ABSENT";
          coverageSources.push(coverageSource("ERC-8004 Reputation Evidence", "QUERIED", reputationEvidenceStatus));
          const reputationCompletenessStatus: EvidenceCoverageSource["status"] =
            scan.historyCoverage === "complete" ? "OBSERVED" : "UNKNOWN";
          coverageSources.push(coverageSource("ERC-8004 Reputation History Completeness", "QUERIED", reputationCompletenessStatus));

          evidence.push({
            source: "ERC-8004 ReputationRegistry",
            kind: "agent_reputation_scan",
            observedAt,
            detail: {
              chainId: primary.chainId,
              totalFeedback: reputationSummary.totalFeedback,
              activeFeedback: reputationSummary.activeFeedback,
              uniqueReviewers: reputationSummary.uniqueReviewers,
              recognizedTags: reputationSummary.recognizedTags,
              unrecognizedTags: reputationSummary.unrecognizedTags,
              scoreEligibleFeedback,
              historyCoverage: scan.historyCoverage,
              blocksScanned: reputationSummary.blocksScanned,
              errorCount: scan.errors.length,
            },
          });

          // Trusted feedback evidence for scoring
          if (trustedFeedbackExists && strongestTrustedRisk !== undefined) {
            evidence.push({
              source: "ERC-8004 ReputationRegistry",
              kind: "agent_trusted_feedback",
              observedAt,
              detail: { strongestRisk: strongestTrustedRisk, scoreEligibleFeedback },
            });
          }
        } catch (e) {
          errors.push(`reputation scan: ${e instanceof Error ? e.message : String(e)}`);
          agentReputation = "unknown";
          coverageSources.push(coverageSource("ERC-8004 Reputation Evidence", "QUERIED", "UNAVAILABLE"));
          coverageSources.push(coverageSource("ERC-8004 Reputation History Completeness", "QUERIED", "UNAVAILABLE"));
        }
      } else {
        coverageSources.push(coverageSource("ERC-8004 Reputation Evidence", "NOT_QUERIED", "UNKNOWN"));
        coverageSources.push(coverageSource("ERC-8004 Reputation History Completeness", "NOT_QUERIED", "UNKNOWN"));
      }
    } else {
      agentReputation = "unknown";
      coverageSources.push(coverageSource("ERC-8004 Reputation Evidence", "NOT_QUERIED", "NOT_APPLICABLE"));
      coverageSources.push(coverageSource("ERC-8004 Reputation History Completeness", "NOT_QUERIED", "NOT_APPLICABLE"));
    }

    // --- Phase 4: targetUrl probe with canonical URL matching ---
    let targetUrlVerified: boolean | undefined;
    let targetUrlRedirectsToPrivate: boolean | undefined;
    let targetUrlStatus: AgentRisk["targetUrlStatus"];

    if (targetUrl && isRegistered && cardVerified && services && services.length > 0) {
      const advertisedEndpoints = services.map(s => s.endpoint).filter((e): e is string => typeof e === "string");
      // Canonical URL matching — exact match only
      const isAdvertised = advertisedEndpoints.some(ep => {
        try {
          const epUrl = new URL(ep);
          const targetUrlObj = new URL(targetUrl);
          return epUrl.origin === targetUrlObj.origin && epUrl.pathname === targetUrlObj.pathname;
        } catch {
          return ep === targetUrl;
        }
      });
      targetUrlVerified = isAdvertised;

      if (isAdvertised) {
        try {
          const probe = await this.agentProvider.probeTargetUrlRedirectsToPrivate(targetUrl);
          targetUrlRedirectsToPrivate = probe.redirectsToPrivate;
          if (probe.error) errors.push(`targetUrl probe: ${probe.error}`);
          if (probe.redirectsToPrivate) {
            targetUrlStatus = "ADVERTISED_REDIRECT_TO_PRIVATE";
            evidence.push({
              source: "OMNI active probe",
              kind: "agent_target_redirect_to_private",
              observedAt,
              detail: { targetUrl, redirectsToPrivate: true },
            });
          } else if (probe.error) {
            targetUrlStatus = "PROBE_UNAVAILABLE";
            evidence.push({ source: "OMNI active probe", kind: "agent_target_probe_unavailable", observedAt, detail: { targetUrl, error: probe.error } });
          } else {
            targetUrlStatus = "ADVERTISED_VERIFIED";
            evidence.push({ source: "OMNI active probe", kind: "agent_target_verified", observedAt, detail: { targetUrl } });
          }
        } catch (e) {
          errors.push(`targetUrl probe: ${e instanceof Error ? e.message : String(e)}`);
        }
      } else {
        targetUrlStatus = "NOT_ADVERTISED";
        evidence.push({
          source: "OMNI active probe",
          kind: "agent_target_not_advertised",
          observedAt,
          detail: { targetUrl },
        });
      }
    } else if (targetUrl && isRegistered && cardVerified && (!services || services.length === 0)) {
      // No services advertised — target URL cannot match
      targetUrlVerified = false;
      targetUrlStatus = "NOT_ADVERTISED";
      evidence.push({
        source: "OMNI active probe",
        kind: "agent_target_not_advertised",
        observedAt,
        detail: { targetUrl, reason: "no_services_advertised" },
      });
    } else if (targetUrl && isRegistered) {
      targetUrlStatus = "PROBE_UNAVAILABLE";
      evidence.push({ source: "OMNI active probe", kind: "agent_target_probe_unavailable", observedAt, detail: { targetUrl, reason: "verified_agent_card_unavailable" } });
    } else if (targetUrl && !isRegistered) {
      targetUrlVerified = false;
      targetUrlStatus = identityProbeStatus === "UNAVAILABLE" ? "PROBE_UNAVAILABLE" : "NOT_APPLICABLE";
    } else {
      targetUrlStatus = "NOT_APPLICABLE";
    }

    // --- Phase 5: assemble agentIdentity dimension ---
    const agentIdentity: AgentRisk["dimensions"]["agentIdentity"] =
      identityProbeStatus === "REGISTERED" ? "registered_verified"
      : identityProbeStatus === "NOT_REGISTERED" ? "not_registered"
      : "unknown";

    // --- Phase 6: assemble AgentRisk extension ---
    const agentRisk: AgentRisk = {
      agentId,
      primaryChainId,
      ...(primaryAgentWallet ? { agentWallet: primaryAgentWallet } : {}),
      ...(primaryRegistrationUri ? { registrationUri: primaryRegistrationUri } : {}),
      ...(agentName ? { agentName } : {}),
      ...(agentDescription ? { agentDescription } : {}),
      dimensions: {
        agentIdentity,
        agentReputation,
        agentValidation,
      },
      chainEvidence: chainResults,
      ...(reputationSummary ? { reputationSummary } : {}),
      ...(services && services.length > 0 ? { services } : {}),
      ...(targetUrlVerified !== undefined ? { targetUrlVerified } : {}),
      ...(targetUrlStatus ? { targetUrlStatus } : {}),
      ...(targetUrlRedirectsToPrivate !== undefined ? { targetUrlRedirectsToPrivate } : {}),
      policyVersion: "omni-agent-risk-v1",
      coverageVersion: AGENT_COVERAGE_MODEL_VERSION,
    };

    // --- Phase 7: RiskAssessment base ---
    const baseAssessment = await this.assessAndJournal({
      subject: { type: "agent", id: canonicalId },
      coverage: { modelVersion: AGENT_COVERAGE_MODEL_VERSION, sources: coverageSources },
      evidence,
      sourceErrors: errors,
    });

    return { ...baseAssessment, agentRisk };
  }
}
