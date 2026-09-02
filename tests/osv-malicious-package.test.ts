import { describe, expect, test } from "bun:test";
import { OsvProvider } from "../src/providers/osv.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
import { extractRiskFeatures } from "../src/domain/risk-features.ts";
import { partitionCompatibleRows } from "../src/domain/risk-evaluation.ts";
import { renderRiskMarkdown } from "../src/http/risk-markdown.ts";
import { RISK_SNAPSHOT_SCHEMA_VERSION, type RiskSnapshot } from "../src/domain/risk.ts";
import { RISK_FEATURE_SCHEMA_VERSION } from "../src/domain/risk-features.ts";

const ordinary = {
  id: "GHSA-ordinary",
  aliases: ["CVE-2026-0001"],
  database_specific: { severity: "high" },
  affected: [{ package: { ecosystem: "npm", name: "demo" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] }]
};

function maliciousRecord(id: string, version: string, modified: string, source: string) {
  return {
    id,
    published: "2026-01-01T00:00:00Z",
    modified,
    summary: `Malicious code in demo (${version})`,
    affected: [{
      package: { ecosystem: "npm", name: "demo", purl: "pkg:npm/demo" },
      versions: [version],
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
      database_specific: {
        source,
        cwes: [{ cweId: "CWE-506", name: "Embedded Malicious Code", description: "malicious fixture" }],
        indicators: { evidence_files: [{ path: "dist/index.js", sha256: "b".repeat(64), tlsh: "T1" + "c".repeat(68) }], package_integrity: [{ filename: `demo-${version}.tgz`, hashes: { sha512_sri: "sha512-fixture" } }] }
      }
    }],
    database_specific: {
      "malicious-packages-origins": [{
        source: "amazon-inspector",
        id: `IN-${id}`,
        modified_time: modified,
        import_time: "2026-01-02T00:00:00Z",
        sha256: "a".repeat(64),
        versions: [version],
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }]
      }]
    }
  };
}

async function query(vulns: unknown[]) {
  const provider = new OsvProvider({ async json() { return { vulns }; } } as never);
  return provider.packageVulnerabilities("npm", "demo", "1.0.0");
}

describe("OSV malicious-package recognition", () => {
  test("groups alias-linked advisories without discarding raw advisory evidence", async () => {
    const first = {
      id: "GHSA-alpha",
      aliases: ["CVE-2026-0001", "GHSA-beta"],
      published: "2026-01-01T00:00:00Z",
      modified: "2026-01-02T00:00:00Z",
      database_specific: { severity: "HIGH", source: "https://source.example/alpha" },
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      affected: [{ package: { ecosystem: "npm", name: "demo" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] }]
    };
    const second = {
      id: "GHSA-beta",
      aliases: ["CVE-2026-0001", "GHSA-alpha"],
      published: "2026-01-03T00:00:00Z",
      modified: "2026-01-04T00:00:00Z",
      database_specific: { severity: "HIGH", source: "https://source.example/beta" },
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      affected: [{ package: { ecosystem: "npm", name: "demo" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] }]
    };
    const result = await query([second, first]);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ id: "GHSA-alpha", severity: "high", advisoryIds: ["GHSA-alpha", "GHSA-beta"] });
    expect(result.findings[0]?.aliases).toEqual(expect.arrayContaining(["CVE-2026-0001", "GHSA-beta"]));
    expect(result.evidence[0]?.detail.advisories).toHaveLength(2);
    expect(result.evidence[0]?.detail.advisories).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "GHSA-alpha", published: "2026-01-01T00:00:00Z", modified: "2026-01-02T00:00:00Z" }),
      expect.objectContaining({ id: "GHSA-beta", published: "2026-01-03T00:00:00Z", modified: "2026-01-04T00:00:00Z" })
    ]));
    const assessment = new RiskEngine().assess({ subject: { type: "package", id: "npm:demo@1.0.0" }, vulnerabilities: result.findings, exploitationChecked: true, evidence: result.evidence });
    expect(assessment.signals.filter(signal => signal.code === "KNOWN_VULNERABILITY")).toHaveLength(1);
    expect(JSON.stringify((await query([first, second])).findings)).toBe(JSON.stringify(result.findings));
  });

  test("keeps lodash advisory evidence complete while grouping its alias overlaps", async () => {
    const advisories = [
      ["GHSA-29mw-wpgm-hmr9", ["CVE-2020-28500"], "MODERATE"],
      ["GHSA-35jh-r3h4-6jhm", ["CVE-2021-23337", "CVE-2026-4800", "GHSA-r5fr-rjxr-66jc"], "HIGH"],
      ["GHSA-f23m-r3pf-42rh", ["CVE-2025-13465", "CVE-2026-2950", "GHSA-xxjr-mmjv-4gpg"], "MODERATE"],
      ["GHSA-r5fr-rjxr-66jc", ["CVE-2021-23337", "CVE-2026-4800", "GHSA-35jh-r3h4-6jhm"], "HIGH"],
      ["GHSA-xxjr-mmjv-4gpg", ["CVE-2025-13465", "CVE-2026-2950", "GHSA-f23m-r3pf-42rh"], "MODERATE"]
    ].map(([id, aliases, severity]) => ({ id, aliases, database_specific: { severity }, affected: [{ package: { ecosystem: "npm", name: "demo" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.18.0" }] }] }] }));
    const result = await query(advisories);
    expect(result.evidence[0]?.detail.vulnerabilityIds).toEqual([
      "GHSA-29mw-wpgm-hmr9",
      "GHSA-35jh-r3h4-6jhm",
      "GHSA-f23m-r3pf-42rh",
      "GHSA-r5fr-rjxr-66jc",
      "GHSA-xxjr-mmjv-4gpg"
    ]);
    expect(result.findings).toHaveLength(3);
    expect(result.findings.filter(finding => finding.severity === "high")).toHaveLength(1);
    expect(result.findings.find(finding => finding.id === "GHSA-35jh-r3h4-6jhm")?.advisoryIds).toEqual(["GHSA-35jh-r3h4-6jhm", "GHSA-r5fr-rjxr-66jc"]);
  });

  test("fails closed on malformed OSV responses", async () => {
    const provider = new OsvProvider({ async json() { return { vulns: { id: "GHSA-invalid" } }; } } as never);
    await expect(provider.packageVulnerabilities("npm", "demo", "1.0.0")).rejects.toThrow("osv_response_malformed");
  });

  test("fails closed when OSV omits the vulnerability array", async () => {
    const provider = new OsvProvider({ async json() { return {}; } } as never);
    await expect(provider.packageVulnerabilities("npm", "demo", "1.0.0")).rejects.toThrow("osv_response_malformed");
  });

  test("fails closed on malformed nested affected-package metadata", async () => {
    const provider = new OsvProvider({ async json() { return { vulns: [{ id: "GHSA-invalid", affected: [{ package: { ecosystem: "npm", name: 123 } }] }] }; } } as never);
    await expect(provider.packageVulnerabilities("npm", "demo", "1.0.0")).rejects.toThrow("osv_response_malformed");
  });

  test("retains withdrawn advisories as evidence without treating them as active findings", async () => {
    const withdrawn = { ...ordinary, withdrawn: "2026-02-01T00:00:00Z" };
    const result = await query([withdrawn]);
    expect(result.findings).toEqual([]);
    expect(result.evidence[0]?.detail.vulnerabilityIds).toEqual([]);
    expect(result.evidence[0]?.detail.advisories).toEqual([expect.objectContaining({ id: "GHSA-ordinary", withdrawn: "2026-02-01T00:00:00Z" })]);
  });

  test("fails closed when affected metadata contradicts the exact OSV query version", async () => {
    await expect(query([{ id: "GHSA-range", database_specific: { severity: "HIGH" }, affected: [{ package: { ecosystem: "npm", name: "other" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] }] }])).rejects.toThrow("osv_advisory_version_mismatch");
  });

  test("keeps exact duplicate advisory IDs deterministic and rejects conflicts", async () => {
    const affected = [{ package: { ecosystem: "npm", name: "demo" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] }];
    const first = { id: "GHSA-duplicate", aliases: ["CVE-2026-0002"], database_specific: { severity: "LOW" }, summary: "same", affected };
    const forward = await query([first, first]);
    const backward = await query([first, first]);
    expect(JSON.stringify(forward.findings)).toBe(JSON.stringify(backward.findings));
    expect(JSON.stringify(forward.evidence[0]?.detail)).toBe(JSON.stringify(backward.evidence[0]?.detail));
    const conflicting = { ...first, database_specific: { severity: "CRITICAL" } };
    await expect(query([first, conflicting])).rejects.toThrow("osv_duplicate_advisory_id_conflict");
  });

  test("separates MAL reports from ordinary vulnerability findings and preserves provenance", async () => {
    const newer = maliciousRecord("MAL-2026-0002", "1.0.1", "2026-02-02T00:00:00Z", "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/demo/MAL-2026-0002.json");
    const older = maliciousRecord("MAL-2026-0001", "1.0.0", "2026-02-01T00:00:00Z", "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/demo/MAL-2026-0001.json");

    const result = await query([newer, ordinary, older]);

    expect(result.findings).toEqual([{ id: "GHSA-ordinary", severity: "high", knownExploited: false, aliases: ["CVE-2026-0001"] }]);
    expect(result.maliciousPackageObservations).toHaveLength(2);
    expect(result.maliciousPackageObservations.map(observation => observation.id)).toEqual(["MAL-2026-0001", "MAL-2026-0002"]);
    expect(result.maliciousPackageObservations[0]).toMatchObject({
      schemaVersion: 1,
      id: "MAL-2026-0001",
      package: { ecosystem: "npm", name: "demo", purl: "pkg:npm/demo" },
      queriedVersion: "1.0.0",
      published: "2026-01-01T00:00:00Z",
      modified: "2026-02-01T00:00:00Z",
      sourceReference: "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/demo/MAL-2026-0001.json",
      affected: [{
        package: { ecosystem: "npm", name: "demo", purl: "pkg:npm/demo" },
        versions: ["1.0.0"],
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
        sourceReference: "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/demo/MAL-2026-0001.json",
        cwes: [{ cweId: "CWE-506", name: "Embedded Malicious Code", description: "malicious fixture" }],
        indicators: { evidenceFiles: [{ path: "dist/index.js", sha256: "b".repeat(64), tlsh: "T1" + "c".repeat(68) }], packageIntegrity: [{ filename: "demo-1.0.0.tgz", hashes: { sha512_sri: "sha512-fixture" } }] }
      }],
      origins: [{ source: "amazon-inspector", id: "IN-MAL-2026-0001", modifiedAt: "2026-02-01T00:00:00Z", importedAt: "2026-01-02T00:00:00Z", sha256: "a".repeat(64), versions: ["1.0.0"], ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] }]
    });
    expect(result.maliciousPackageObservations[1]).toMatchObject({ id: "MAL-2026-0002", queriedVersion: "1.0.0", modified: "2026-02-02T00:00:00Z" });
    expect(result.maliciousPackageObservations).not.toHaveProperty("severity");
    const reordered = await query([older, ordinary, newer]);
    expect(JSON.stringify(reordered.maliciousPackageObservations)).toBe(JSON.stringify(result.maliciousPackageObservations));
  });

  test("keeps ordinary OSV vulnerability behavior unchanged", async () => {
    const result = await query([ordinary]);
    expect(result.findings).toEqual([{ id: "GHSA-ordinary", severity: "high", knownExploited: false, aliases: ["CVE-2026-0001"] }]);
    expect(result.maliciousPackageObservations).toEqual([]);
  });

  test("does not create MAL observations when OSV returns no active match", async () => {
    await expect(query([])).resolves.toMatchObject({ findings: [], maliciousPackageObservations: [] });
  });

  test("does not treat an explicitly withdrawn MAL record as active", async () => {
    const withdrawn = { ...maliciousRecord("MAL-2026-0003", "1.0.2", "2026-02-03T00:00:00Z", "https://github.com/ossf/malicious-packages/blob/main/osv/withdrawn/npm/demo/MAL-2026-0003.json"), withdrawn: "2026-02-04T00:00:00Z" };
    await expect(query([withdrawn])).resolves.toMatchObject({ findings: [], maliciousPackageObservations: [] });
  });

  test("normalizes nested version and duplicate-id ordering deterministically", async () => {
    const first = maliciousRecord("MAL-2026-0004", "1.0.4", "2026-02-04T00:00:00Z", "https://example.com/source-b");
    first.affected[0]!.versions.push("0.9.0");
    const reordered = structuredClone(first);
    reordered.affected[0]!.versions.reverse();
    const firstResult = await query([first]);
    const secondResult = await query([reordered]);
    expect(JSON.stringify(firstResult.maliciousPackageObservations)).toBe(JSON.stringify(secondResult.maliciousPackageObservations));

    const duplicateA = maliciousRecord("MAL-2026-0005", "1.0.5", "2026-02-05T00:00:00Z", "https://example.com/source-a");
    const duplicateB = maliciousRecord("MAL-2026-0005", "1.0.5", "2026-02-06T00:00:00Z", "https://example.com/source-b");
    const forward = await query([duplicateA, duplicateB]);
    const backward = await query([duplicateB, duplicateA]);
    expect(JSON.stringify(forward.maliciousPackageObservations)).toBe(JSON.stringify(backward.maliciousPackageObservations));
  });

  test("preserves provider timeout/error semantics", async () => {
    const provider = new OsvProvider({ async json() { throw new Error("upstream 504 api.osv.dev"); } } as never);
    await expect(provider.packageVulnerabilities("npm", "demo", "1.0.0")).rejects.toThrow("upstream 504 api.osv.dev");
  });

  test("keeps MAL observations observation-only under the current risk policy", () => {
    const base: RiskSnapshot = {
      subject: { type: "package", id: "npm:demo@1.0.0" },
      vulnerabilities: [],
      exploitationChecked: true,
      threatIntelChecked: true,
      threatFindings: [],
      evidence: []
    };
    const withMal: RiskSnapshot = {
      ...base,
      maliciousPackageObservations: [{
        schemaVersion: 1,
        id: "MAL-2026-0001",
        package: { ecosystem: "npm", name: "demo" },
        queriedVersion: "1.0.0",
        affected: [],
        origins: []
      }]
    };
    const before = new RiskEngine().assess(base);
    const after = new RiskEngine().assess(withMal);
    expect({ riskScore: after.riskScore, recommendation: after.recommendation, signals: after.signals }).toEqual({ riskScore: before.riskScore, recommendation: before.recommendation, signals: before.signals });
    expect(after.maliciousPackageObservations).toEqual(withMal.maliciousPackageObservations);
    const markdown = renderRiskMarkdown(after);
    expect(markdown).toContain("## Malicious Package Observations");
    expect(markdown).toContain("MAL-2026-0001");
    expect(markdown).not.toContain('"severity"');
  });

  test("keeps old persisted snapshots and feature rows replay-compatible", () => {
    const oldSnapshot: RiskSnapshot = { subject: { type: "package", id: "npm:demo@1.0.0" }, vulnerabilities: [], exploitationChecked: true, threatIntelChecked: true, threatFindings: [], evidence: [] };
    const newSnapshot: RiskSnapshot = { ...oldSnapshot, maliciousPackageObservations: [{ schemaVersion: 1, id: "MAL-2026-0001", package: { ecosystem: "npm", name: "demo" }, queriedVersion: "1.0.0", affected: [], origins: [] }] };
    expect(extractRiskFeatures(oldSnapshot)).toEqual(extractRiskFeatures(newSnapshot));
    expect(new RiskEngine().assess(oldSnapshot)).toMatchObject({ riskScore: new RiskEngine().assess(newSnapshot).riskScore, recommendation: new RiskEngine().assess(newSnapshot).recommendation });
    expect(partitionCompatibleRows([{ snapshotSchemaVersion: RISK_SNAPSHOT_SCHEMA_VERSION, featureSchemaVersion: RISK_FEATURE_SCHEMA_VERSION, subjectType: "package" as const, id: "old" }], RISK_SNAPSHOT_SCHEMA_VERSION, RISK_FEATURE_SCHEMA_VERSION).incompatible).toEqual([]);
  });
});
