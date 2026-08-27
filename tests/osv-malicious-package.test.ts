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
  database_specific: { severity: "high" }
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

  test("preserves provider timeout/error semantics", async () => {
    const provider = new OsvProvider({ async json() { throw new Error("upstream 504 api.osv.dev"); } } as never);
    await expect(provider.packageVulnerabilities("npm", "demo", "1.0.0")).rejects.toThrow("upstream 504 api.osv.dev");
  });

  test("keeps MAL observations observation-only under omni-risk-v1", () => {
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
