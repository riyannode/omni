import type { DependencyObservation, ExactDependencyCoordinate, RepositoryEvidence, RepositoryThreatIntelObservation, RiskAssessment, RiskSnapshot, ThreatFinding } from "./domain/risk.ts";
import { RiskEngine } from "./domain/risk-engine.ts";
import type { ObservedPaymentRequirement, X402EndpointPreflight } from "./domain/x402-preflight-consistency.ts";
import { CachedLoader } from "./data/cache.ts";
import type { HistoryStore } from "./data/history.ts";
import type { ThreatIntelStore } from "./data/threat-intel.ts";
import { extractRiskFeatures } from "./domain/risk-features.ts";
import type { AssessmentJournal } from "./data/assessment-journal.ts";
import { NoopAssessmentJournal } from "./data/assessment-journal.ts";
import { OsvProvider } from "./providers/osv.ts";
import { CisaKevProvider } from "./providers/cisa-kev.ts";
import { ScorecardProvider } from "./providers/scorecard.ts";
import { GitHubRepositoryProvider } from "./providers/github-repository.ts";
import { DepsDevProvider } from "./providers/deps-dev.ts";
import { NpmRegistryProvider } from "./providers/npm-registry.ts";
import { CircleDiscoveryProvider } from "./providers/circle-discovery.ts";
import { X402Probe } from "./providers/x402-probe.ts";

const REPOSITORY_DEPENDENCY_ENRICHMENT_LIMIT = 24;
const REPOSITORY_ENRICHMENT_CONCURRENCY = 4;
const REPOSITORY_ASSESSMENT_CACHE_TTL_SECONDS = 600;
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
  const result = (): RepositoryThreatIntelObservation => ({ ...observation, packagesInspected, findings, limitations });

  if (utf8Bytes(JSON.stringify(result())) <= MAX_REPOSITORY_THREAT_INTEL_BYTES) return result();

  limitations = boundedLimitations([...limitations, "threat_intel_payload_truncated"]).values;
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
  const fallback: RepositoryThreatIntelObservation = { ...observation, packagesInspected: [], findings: [], errors: [], limitations: fallbackLimitations };
  if (utf8Bytes(JSON.stringify(fallback)) <= MAX_REPOSITORY_THREAT_INTEL_BYTES) return fallback;

  return { status: observation.status, packagesInspected: [], findings: [], errors: [], limitations: [] };
}

function finalizeRepositoryThreatIntelObservation(status: RepositoryThreatIntelObservation["status"], packagesInspected: ExactDependencyCoordinate[], findings: RepositoryThreatIntelObservation["findings"], errors: string[], limitations: string[]): RepositoryThreatIntelObservation {
  const boundedErrors = boundedEntries(errors, MAX_REPOSITORY_THREAT_INTEL_ERROR_ENTRIES, "errors");
  const rawLimitations = [...limitations];
  if (boundedErrors.overflow) rawLimitations.push(`threat_intel_errors_truncated:${MAX_REPOSITORY_THREAT_INTEL_ERROR_ENTRIES}_of_${errors.length}`);
  if (boundedErrors.entryTruncated) rawLimitations.push("threat_intel_error_entry_truncated");
  if (rawLimitations.some(entry => utf8Bytes(entry) > MAX_REPOSITORY_THREAT_INTEL_ENTRY_BYTES)) rawLimitations.push("threat_intel_limitation_entry_truncated");
  const bounded = boundedLimitations(rawLimitations);
  return fitRepositoryThreatIntelObservation({ status, packagesInspected: [...packagesInspected], findings: uniqueSortedFindings(findings), errors: boundedErrors.values, limitations: bounded.values });
}

export async function collectRepositoryThreatIntel(threatIntel: ThreatIntelStore, coordinates: ExactDependencyCoordinate[], deferred: number, selectedCount: number): Promise<RepositoryThreatIntelObservation> {
  if (coordinates.length === 0) return finalizeRepositoryThreatIntelObservation("NOT_CHECKED", [], [], [], ["no_exact_dependencies_selected"]);
  const findingsByCoordinate = new Map<string, RepositoryThreatIntelObservation["findings"]>();
  const errors: string[] = [];
  const limitations = deferred > 0 ? [`dependency_enrichment_limit_reached:${deferred}_of_${selectedCount}_deferred`] : [];
  let unavailable = false;
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
        unavailable = true;
        errors.push(`threat_intel ${identity}: ${item.error}`);
        limitations.push(`threat_intel_lookup_failed:${item.coordinate.name}@${item.coordinate.version}`);
        continue;
      }
      if (!item.result.checked) {
        unavailable = true;
        limitations.push(`threat_intel_unavailable:${item.coordinate.name}@${item.coordinate.version}`);
      }
      const normalized: RepositoryThreatIntelObservation["findings"] = [];
      let fieldTruncated = false;
      for (const finding of Array.isArray(item.result.findings) ? item.result.findings : []) {
        const bounded = normalizeThreatFinding(item.coordinate, finding);
        normalized.push(bounded.value);
        fieldTruncated ||= bounded.truncated;
      }
      const unique = uniqueSortedFindings(normalized);
      if (fieldTruncated) limitations.push(`threat_intel_finding_field_truncated:${identity}`);
      if (unique.length > MAX_REPOSITORY_THREAT_FINDINGS_PER_PACKAGE) {
        limitations.push(`threat_intel_findings_truncated:${identity}:${MAX_REPOSITORY_THREAT_FINDINGS_PER_PACKAGE}_of_${unique.length}`);
        findingsByCoordinate.set(identity, unique.slice(0, MAX_REPOSITORY_THREAT_FINDINGS_PER_PACKAGE));
      } else findingsByCoordinate.set(identity, unique);
    }
  }
  const allFindings = uniqueSortedFindings([...findingsByCoordinate.values()].flat());
  if (allFindings.length > MAX_REPOSITORY_THREAT_FINDINGS_TOTAL) limitations.push(`threat_intel_total_findings_truncated:${MAX_REPOSITORY_THREAT_FINDINGS_TOTAL}_of_${allFindings.length}`);
  const retained = allFindings.slice(0, MAX_REPOSITORY_THREAT_FINDINGS_TOTAL);
  return finalizeRepositoryThreatIntelObservation(unavailable ? "UNAVAILABLE" : "CHECKED", coordinates, retained, errors, limitations);
}

function repositoryThreatIntelDetail(observation: RepositoryThreatIntelObservation): Record<string, unknown> {
  return { status: observation.status, packagesInspected: observation.packagesInspected, findings: observation.findings, errors: observation.errors, limitations: observation.limitations };
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
    private readonly depsDev: DepsDevProvider = {} as DepsDevProvider
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
    const key = `assessment:package:${ecosystem}:${name}:${version}`;
    return this.cache.getOrLoad(key, 300, async () => {
      const errors: string[] = [];
      let vulnerabilities: RiskSnapshot["vulnerabilities"];
      let exploitationChecked = false;
      let packageSupplyChain: RiskSnapshot["packageSupplyChain"];
      let maliciousPackageObservations: RiskSnapshot["maliciousPackageObservations"] = [];
      let threatIntelChecked = false;
      let threatFindings: ThreatFinding[] = [];
      const evidence: RiskSnapshot["evidence"] = [];

      try {
        const osv = await this.osv.packageVulnerabilities(ecosystem, name, version);
        vulnerabilities = osv.findings;
        maliciousPackageObservations = osv.maliciousPackageObservations ?? [];
        evidence.push(...osv.evidence);
        if (vulnerabilities.length > 0) {
          try {
            const kev = await this.kev.mark(vulnerabilities.flatMap(v => [v.id, ...v.aliases]));
            for (const vuln of vulnerabilities) {
              vuln.knownExploited = kev.exploited.has(vuln.id) || vuln.aliases.some(alias => kev.exploited.has(alias));
            }
            exploitationChecked = true;
            evidence.push(kev.evidence);
          } catch (error) { errors.push(`CISA KEV: ${error instanceof Error ? error.message : "unknown error"}`); }
        } else exploitationChecked = true;
      } catch (error) { errors.push(`OSV: ${error instanceof Error ? error.message : "unknown error"}`); }

      if (ecosystem.toLowerCase() === "npm") {
        try {
          const registry = await this.npm.packageMetadata(name, version);
          packageSupplyChain = registry.signals;
          evidence.push(registry.evidence);
        } catch (error) { errors.push(`npm Registry: ${error instanceof Error ? error.message : "unknown error"}`); }
      }

      try {
        const threat = await this.threatIntel.lookupPackage(ecosystem, name, version);
        threatIntelChecked = threat.checked;
        threatFindings = threat.findings;
        if (!threat.checked) errors.push("Threat intelligence: no licensed feed loaded");
        else evidence.push({ source: "OMNI threat intelligence", kind: "package_ioc_lookup", observedAt: new Date().toISOString(), detail: { matches: threat.findings.length } });
      } catch (error) { errors.push(`Threat intelligence: ${error instanceof Error ? error.message : "unknown error"}`); }

      return this.assessAndJournal({
        subject: { type: "package", id: `${ecosystem}:${name}@${version}` },
        ...(vulnerabilities === undefined ? {} : { vulnerabilities }), exploitationChecked,
        ...(packageSupplyChain ? { packageSupplyChain } : {}),
        ...(maliciousPackageObservations.length > 0 ? { maliciousPackageObservations } : {}),
        threatIntelChecked, threatFindings,
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
      return this.cache.getOrLoad(`assessment:repo:${identity.repository}:${identity.resolvedCommitSha}`, REPOSITORY_ASSESSMENT_CACHE_TTL_SECONDS, async () => {
        const repositoryEvidence = await this.github.collectResolved(owner, repo, identity);
        return this.repositoryRiskFromEvidence(repositoryEvidence);
      });
    }
    catch (error) {
      const repositoryEvidence: RepositoryEvidence = { target: { repository: canonicalRepository ?? target }, securityFiles: [], dependencies: { exact: [], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } }, dependencyObservations: [], dependencyThreatIntel: { status: "NOT_CHECKED", packagesInspected: [], findings: [], errors: [], limitations: ["github_collection_unavailable"] }, coverage: { status: "partial", treeEntriesInspected: 0, filesInspected: 0, bytesInspected: 0, limitations: ["github_collection_unavailable"] }, sourceErrors: [`GitHub: ${error instanceof Error ? error.message : "unknown error"}`] };
      return this.repositoryRiskFromEvidence(repositoryEvidence);
    }
  }

  private async repositoryRiskFromEvidence(repositoryEvidence: RepositoryEvidence): Promise<RiskAssessment> {
    const evidence: RiskSnapshot["evidence"] = [{ source: "GitHub", kind: "repository_primary_evidence", observedAt: new Date().toISOString(), detail: { repository: repositoryEvidence.target.repository, ...(repositoryEvidence.target.resolvedCommitSha ? { resolvedCommitSha: repositoryEvidence.target.resolvedCommitSha } : {}), coverage: repositoryEvidence.coverage.status, limitations: repositoryEvidence.coverage.limitations } }];
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
    const expected = { repository: repositoryEvidence.target.repository, ...(repositoryEvidence.target.resolvedCommitSha ? { commit: repositoryEvidence.target.resolvedCommitSha } : {}) };
    const threatIntelObservation = await collectRepositoryThreatIntel(this.threatIntel, enriched, deferred, selected.length);
    repositoryEvidence.dependencyThreatIntel = threatIntelObservation;
    evidence.push({ source: "OMNI threat intelligence", kind: "repository_dependency_ioc_lookup", observedAt: new Date().toISOString(), detail: repositoryThreatIntelDetail(threatIntelObservation) });
    for (let offset = 0; offset < enriched.length; offset += REPOSITORY_ENRICHMENT_CONCURRENCY) {
      const chunk = enriched.slice(offset, offset + REPOSITORY_ENRICHMENT_CONCURRENCY);
      await Promise.all(chunk.map(async coordinate => {
        try {
          const observed = await this.depsDev.packageVersion(coordinate, expected);
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
    evidence[0]!.detail.collectorErrors = [...repositoryEvidence.sourceErrors];
    evidence[0]!.detail.coverage = repositoryEvidence.coverage.status;
    evidence[0]!.detail.limitations = [...new Set(repositoryEvidence.coverage.limitations)].sort();
    return this.assessAndJournal({ subject: { type: "repository", id: repositoryEvidence.target.repository }, ...(scorecard === undefined ? {} : { scorecard }), repositoryEvidence, evidence, sourceErrors });
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
}
