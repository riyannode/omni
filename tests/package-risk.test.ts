import { describe, expect, test } from "bun:test";
import { CachedLoader, createCache } from "../src/data/cache.ts";
import { OmniIntelligence } from "../src/services.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
import type { Evidence, VulnerabilityFinding } from "../src/domain/risk.ts";

type FixtureOptions = {
  findings?: VulnerabilityFinding[];
  osvFailure?: boolean;
  npmFailure?: boolean;
  kevFailure?: boolean;
  threat?: { checked: boolean; findings: [] };
};

function evidence(source: string, kind: string): Evidence {
  return { source, kind, observedAt: "2026-01-01T00:00:00.000Z", detail: {} };
}

function fixture(options: FixtureOptions = {}) {
  const calls = { kev: 0 };
  const findings = options.findings ?? [];
  const osv = {
    async packageVulnerabilities() {
      if (options.osvFailure) throw new Error("osv_timeout");
      return { findings, maliciousPackageObservations: [], evidence: [evidence("OSV", "package_vulnerabilities")] };
    }
  };
  const kev = {
    async mark() {
      calls.kev += 1;
      if (options.kevFailure) throw new Error("kev_timeout");
      return { exploited: new Set<string>(), evidence: { ...evidence("CISA KEV", "known_exploitation"), detail: { matched: [] } } };
    }
  };
  const npm = {
    async packageMetadata() {
      if (options.npmFailure) throw new Error("registry_timeout");
      return {
        signals: { registry: "npm" as const, deprecated: false, hasInstallScript: false, integrityPresent: true, signatureCount: 1, maintainerCount: 1 },
        evidence: evidence("npm Registry", "package_supply_chain_metadata")
      };
    }
  };
  const threat = options.threat ?? { checked: true, findings: [] as [] };
  const omni = new OmniIntelligence(
    new RiskEngine(), new CachedLoader(createCache()), osv as never, kev as never, {} as never, npm as never,
    {} as never, {} as never, {} as never,
    { async lookupEndpoint() { return { checked: false, findings: [] }; }, async lookupPackage() { return threat; }, async status() { return { available: threat.checked, configured: threat.checked, activeIndicators: 0, sources: 0 }; } } as never
  );
  return { omni, calls };
}

describe("package evidence coverage", () => {
  test("reaches proceed when all applicable package evidence resolves cleanly", async () => {
    const result = await fixture().omni.packageRisk("npm", "demo", "1.0.0");
    expect(result.recommendation).toBe("proceed");
    expect(result.riskScore).toBe(0);
    expect(result.evidenceCoverage).toBe(1);
    expect(result.coverage).toMatchObject({ modelVersion: "package-coverage-v2", resolvedWeight: 3, applicableWeight: 3 });
    expect(result.coverage?.sources).toEqual([
      { source: "OSV", execution: "QUERIED", status: "ABSENT", weight: 1 },
      { source: "CISA KEV", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 1 },
      { source: "npm Registry", execution: "QUERIED", status: "OBSERVED", weight: 1 },
      { source: "Threat Intelligence", execution: "QUERIED", status: "ABSENT", weight: 1 }
    ]);
  });

  test("keeps npm failure applicable and unavailable in coverage", async () => {
    const result = await fixture({ npmFailure: true }).omni.packageRisk("npm", "demo", "1.0.0");
    expect(result.coverage).toMatchObject({ resolvedWeight: 2, applicableWeight: 3 });
    expect(result.evidenceCoverage).toBe(0.67);
    expect(result.coverage?.sources).toContainEqual({ source: "npm Registry", execution: "QUERIED", status: "UNAVAILABLE", weight: 1 });
    expect(result.sourceErrors).toContain("npm Registry: registry_timeout");
  });

  test("never lowers risk when an applicable source fails", async () => {
    const clean = await fixture({ threat: { checked: true, findings: [] } }).omni.packageRisk("npm", "demo", "1.0.0");
    const failed = await fixture({ npmFailure: true, threat: { checked: true, findings: [] } }).omni.packageRisk("npm", "demo", "1.0.0");
    expect(failed.riskScore).toBeGreaterThanOrEqual(clean.riskScore);
  });

  test("keeps zero applicable resolution fail-closed", async () => {
    const result = await fixture({ osvFailure: true, npmFailure: true, threat: { checked: false, findings: [] } }).omni.packageRisk("npm", "demo", "1.0.0");
    expect(result.evidenceCoverage).toBe(0);
    expect(result.riskScore).toBe(50);
    expect(result.recommendation).toBe("manual_review");
  });

  test("keeps an unavailable OSV source fail-closed even when other sources resolve", async () => {
    const result = await fixture({ osvFailure: true, threat: { checked: true, findings: [] } }).omni.packageRisk("npm", "demo", "1.0.0");
    expect(result.evidenceCoverage).toBe(0.5);
    expect(result.riskScore).toBe(50);
    expect(result.recommendation).toBe("manual_review");
    expect(result.coverage?.sources).toContainEqual({ source: "CISA KEV", execution: "NOT_QUERIED", status: "UNKNOWN", weight: 1 });
  });

  test("does not query CISA when OSV has no correlatable vulnerabilities", async () => {
    const { omni, calls } = fixture();
    const result = await omni.packageRisk("npm", "demo", "1.0.0");
    expect(calls.kev).toBe(0);
    expect(result.coverage?.sources).toContainEqual({ source: "CISA KEV", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 1 });
  });

  test("keeps non-correlatable vulnerability exploitation applicability explicit", async () => {
    const result = await fixture({ findings: [{ id: "GHSA-only", severity: "high", knownExploited: false, aliases: [] }] }).omni.packageRisk("npm", "demo", "1.0.0");
    expect(result.dimensions.knownExploitation).toBe("low");
    expect(result.coverage?.sources).toContainEqual({ source: "CISA KEV", execution: "NOT_QUERIED", status: "NOT_APPLICABLE", weight: 1 });
  });

  test("records a successful negative CISA lookup as absent", async () => {
    const { omni, calls } = fixture({ findings: [{ id: "GHSA-demo", severity: "high", knownExploited: false, aliases: ["CVE-2026-0001"] }] });
    const result = await omni.packageRisk("npm", "demo", "1.0.0");
    expect(calls.kev).toBe(1);
    expect(result.coverage?.sources).toContainEqual({ source: "CISA KEV", execution: "QUERIED", status: "ABSENT", weight: 1 });
    expect(result.evidence.some(item => item.source === "CISA KEV")).toBe(true);
  });

  test("records applicable CISA failure as unavailable", async () => {
    const result = await fixture({ findings: [{ id: "GHSA-demo", severity: "high", knownExploited: false, aliases: ["CVE-2026-0001"] }], kevFailure: true }).omni.packageRisk("npm", "demo", "1.0.0");
    expect(result.coverage?.sources).toContainEqual({ source: "CISA KEV", execution: "QUERIED", status: "UNAVAILABLE", weight: 1 });
    expect(result.sourceErrors).toContain("CISA KEV: kev_timeout");
  });

  test("does not convert unavailable threat intelligence into absent", async () => {
    const result = await fixture({ threat: { checked: false, findings: [] } }).omni.packageRisk("npm", "demo", "1.0.0");
    expect(result.coverage?.sources).toContainEqual({ source: "Threat Intelligence", execution: "QUERIED", status: "UNAVAILABLE", weight: 1 });
    expect(result.sourceErrors).toContain("Threat intelligence: no licensed feed loaded");
  });

  test("preserves the four exact package golden-case outcomes under deterministic fixtures", async () => {
    const circle = await fixture({ threat: { checked: false, findings: [] } }).omni.packageRisk("npm", "@circle-fin/x402-batching", "3.4.0");
    const vulnerable = await fixture({ findings: [{ id: "GHSA-xvch-5gv4-984h", severity: "critical", knownExploited: false, aliases: ["CVE-2021-44906"] }], threat: { checked: false, findings: [] } }).omni.packageRisk("npm", "minimist", "1.2.5");
    const fixed = await fixture({ threat: { checked: false, findings: [] } }).omni.packageRisk("npm", "minimist", "1.2.6");
    const lodash = await fixture({ findings: [
      { id: "GHSA-29mw-wpgm-hmr9", severity: "medium", knownExploited: false, aliases: ["CVE-2020-28500"] },
      { id: "GHSA-35jh-r3h4-6jhm", severity: "high", knownExploited: false, aliases: ["CVE-2021-23337", "GHSA-r5fr-rjxr-66jc"] },
      { id: "GHSA-f23m-r3pf-42rh", severity: "medium", knownExploited: false, aliases: ["CVE-2025-13465", "GHSA-xxjr-mmjv-4gpg"] }
    ], threat: { checked: false, findings: [] } }).omni.packageRisk("npm", "lodash", "4.17.20");

    expect({ score: circle.riskScore, recommendation: circle.recommendation, coverage: circle.evidenceCoverage, signals: circle.signals }).toEqual({ score: 5, recommendation: "proceed", coverage: 0.67, signals: [] });
    expect({ score: vulnerable.riskScore, recommendation: vulnerable.recommendation, coverage: vulnerable.evidenceCoverage, severity: vulnerable.dimensions.knownVulnerabilities }).toEqual({ score: 90, recommendation: "do_not_proceed", coverage: 0.75, severity: "critical" });
    expect({ score: fixed.riskScore, recommendation: fixed.recommendation, coverage: fixed.evidenceCoverage, signals: fixed.signals }).toEqual({ score: 5, recommendation: "proceed", coverage: 0.67, signals: [] });
    expect({ score: lodash.riskScore, recommendation: lodash.recommendation, coverage: lodash.evidenceCoverage, highSignals: lodash.signals.filter(signal => signal.code === "KNOWN_VULNERABILITY") }).toMatchObject({ score: 65, recommendation: "manual_review", coverage: 0.75, highSignals: [{ detail: { id: "GHSA-35jh-r3h4-6jhm" } }] });
  });
});
