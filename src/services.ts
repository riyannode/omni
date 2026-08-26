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

function coordinateIdentity(coordinate: { ecosystem: string; name: string; version: string }): string { return `${coordinate.ecosystem}:${coordinate.name}@${coordinate.version}`; }

async function collectRepositoryThreatIntel(threatIntel: ThreatIntelStore, coordinates: ExactDependencyCoordinate[], deferred: number, selectedCount: number): Promise<RepositoryThreatIntelObservation> {
  if (coordinates.length === 0) return { status: "NOT_CHECKED", packagesInspected: [], findings: [], errors: [], limitations: ["no_exact_dependencies_selected"] };
  const findings: RepositoryThreatIntelObservation["findings"] = [];
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
      if ("error" in item) {
        unavailable = true;
        errors.push(`threat_intel ${coordinateIdentity(item.coordinate)}: ${item.error}`);
        limitations.push(`threat_intel_lookup_failed:${item.coordinate.name}@${item.coordinate.version}`);
        continue;
      }
      if (!item.result.checked) {
        unavailable = true;
        limitations.push(`threat_intel_unavailable:${item.coordinate.name}@${item.coordinate.version}`);
      }
      findings.push(...item.result.findings.map(finding => ({ coordinate: item.coordinate, finding })));
    }
  }
  return { status: unavailable ? "UNAVAILABLE" : "CHECKED", packagesInspected: coordinates, findings, errors, limitations: [...new Set(limitations)].sort() };
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
      let threatIntelChecked = false;
      let threatFindings: ThreatFinding[] = [];
      const evidence: RiskSnapshot["evidence"] = [];

      try {
        const osv = await this.osv.packageVulnerabilities(ecosystem, name, version);
        vulnerabilities = osv.findings;
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
        ...(packageSupplyChain ? { packageSupplyChain } : {}), threatIntelChecked, threatFindings,
        evidence, sourceErrors: errors
      });
    });
  }

  async repositoryRisk(owner: string, repo: string): Promise<RiskAssessment> {
    const target = `github.com/${owner}/${repo}`;
    try {
      const identity = await this.github.resolve(owner, repo);
      return this.cache.getOrLoad(`assessment:repo:${owner}/${repo}:${identity.resolvedCommitSha}`, 1800, async () => {
        const repositoryEvidence = await this.github.collectResolved(owner, repo, identity);
        return this.repositoryRiskFromEvidence(owner, repo, repositoryEvidence);
      });
    }
    catch (error) {
      const repositoryEvidence: RepositoryEvidence = { target: { repository: target }, securityFiles: [], dependencies: { exact: [], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } }, dependencyObservations: [], dependencyThreatIntel: { status: "NOT_CHECKED", packagesInspected: [], findings: [], errors: [], limitations: ["github_collection_unavailable"] }, coverage: { status: "partial", treeEntriesInspected: 0, filesInspected: 0, bytesInspected: 0, limitations: ["github_collection_unavailable"] }, sourceErrors: [`GitHub: ${error instanceof Error ? error.message : "unknown error"}`] };
      return this.repositoryRiskFromEvidence(owner, repo, repositoryEvidence);
    }
  }

  private async repositoryRiskFromEvidence(owner: string, repo: string, repositoryEvidence: RepositoryEvidence): Promise<RiskAssessment> {
    const evidence: RiskSnapshot["evidence"] = [{ source: "GitHub", kind: "repository_primary_evidence", observedAt: new Date().toISOString(), detail: { repository: repositoryEvidence.target.repository, ...(repositoryEvidence.target.resolvedCommitSha ? { resolvedCommitSha: repositoryEvidence.target.resolvedCommitSha } : {}), coverage: repositoryEvidence.coverage.status, limitations: repositoryEvidence.coverage.limitations } }];
    const sourceErrors: string[] = []; let scorecard: number | undefined;
    try { const result = await this.scorecard.repository(owner, repo); scorecard = result.score; evidence.push(result.evidence); }
    catch (error) { sourceErrors.push(`OpenSSF Scorecard: ${error instanceof Error ? error.message : "unknown error"}`); }
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
    evidence.push({ source: "OMNI threat intelligence", kind: "repository_dependency_ioc_lookup", observedAt: new Date().toISOString(), detail: threatIntelObservation as unknown as Record<string, unknown> });
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
    return this.assessAndJournal({ subject: { type: "repository", id: `github.com/${owner}/${repo}` }, ...(scorecard === undefined ? {} : { scorecard }), repositoryEvidence, evidence, sourceErrors });
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
          const probe = await this.probe.unpaidGet(resource, listedOnCircle === true);
          activeProbeChecked = true; responseStatus = probe.status; paymentOptions = probe.paymentOptions; evidence.push(probe.evidence);
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
