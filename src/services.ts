import type { RiskAssessment, RiskSnapshot, ThreatFinding } from "./domain/risk.ts";
import { RiskEngine } from "./domain/risk-engine.ts";
import { CachedLoader } from "./data/cache.ts";
import type { HistoryStore } from "./data/history.ts";
import type { ThreatIntelStore } from "./data/threat-intel.ts";
import { extractRiskFeatures } from "./domain/risk-features.ts";
import type { AssessmentJournal } from "./data/assessment-journal.ts";
import { NoopAssessmentJournal } from "./data/assessment-journal.ts";
import { OsvProvider } from "./providers/osv.ts";
import { CisaKevProvider } from "./providers/cisa-kev.ts";
import { ScorecardProvider } from "./providers/scorecard.ts";
import { NpmRegistryProvider } from "./providers/npm-registry.ts";
import { CircleDiscoveryProvider } from "./providers/circle-discovery.ts";
import { X402Probe } from "./providers/x402-probe.ts";

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
    private readonly journal: AssessmentJournal = new NoopAssessmentJournal()
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
    const key = `assessment:repo:${owner}/${repo}`;
    return this.cache.getOrLoad(key, 1800, async () => {
      const errors: string[] = [];
      const evidence: RiskSnapshot["evidence"] = [];
      let scorecard: number | undefined;
      try {
        const result = await this.scorecard.repository(owner, repo);
        scorecard = result.score;
        evidence.push(result.evidence);
      } catch (error) { errors.push(`OpenSSF Scorecard: ${error instanceof Error ? error.message : "unknown error"}`); }
      return this.assessAndJournal({ subject: { type: "repository", id: `github.com/${owner}/${repo}` }, ...(scorecard === undefined ? {} : { scorecard }), evidence, sourceErrors: errors });
    });
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

  async endpointPreflight(resource: string): Promise<RiskAssessment> {
    const key = `assessment:endpoint:${resource}`;
    return this.cache.getOrLoad(key, 60, async () => {
      const errors: string[] = [];
      const evidence: RiskSnapshot["evidence"] = [];
      let listedOnCircle: boolean | undefined, supportsGateway: boolean | undefined, supportsVanilla: boolean | undefined;
      let responseStatus: number | undefined, paymentOptions: number | undefined, listedMethod: string | undefined;
      let payTo: string | undefined, network: string | undefined, priceAtomic: string | undefined;
      let activeProbeChecked = false, historyChecked = false, threatIntelChecked = false;
      let endpointHistory: RiskSnapshot["endpointHistory"];
      let threatFindings: ThreatFinding[] = [];

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

      return this.assessAndJournal({
        subject: { type: "x402_endpoint", id: resource },
        endpoint: { ...(listedOnCircle === undefined ? {} : { listedOnCircle }), ...(supportsGateway === undefined ? {} : { supportsGateway }), ...(supportsVanilla === undefined ? {} : { supportsVanilla }), ...(responseStatus === undefined ? {} : { responseStatus }), ...(paymentOptions === undefined ? {} : { paymentOptions }), ...(payTo ? { payTo } : {}), ...(network ? { network } : {}), ...(priceAtomic ? { priceAtomic } : {}) },
        activeProbeChecked, historyChecked, ...(endpointHistory ? { endpointHistory } : {}), threatIntelChecked, threatFindings,
        evidence, sourceErrors: errors
      });
    });
  }
}
