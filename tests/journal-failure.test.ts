import { describe, expect, test } from "bun:test";
import { CachedLoader, createCache } from "../src/data/cache.ts";
import { OmniIntelligence } from "../src/services.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
import type { AssessmentJournal } from "../src/data/assessment-journal.ts";

const evidence = { source: "test", kind: "fixture", observedAt: "2026-01-01T00:00:00.000Z", detail: {} };

test("journal persistence failure never changes the authoritative assessment", async () => {
  const journal: AssessmentJournal = {
    async record(): Promise<string> { throw new Error("database unavailable"); },
    async labelAssessment(): Promise<void> {},
    async loadLabelled() { return []; }
  };
  const omni = new OmniIntelligence(
    new RiskEngine(),
    new CachedLoader(createCache()),
    { async packageVulnerabilities() { return { findings: [], evidence: [evidence] }; } } as never,
    {} as never,
    {} as never,
    { async packageMetadata() { return { signals: { registry: "npm", deprecated: false, hasInstallScript: false, integrityPresent: true, signatureCount: 0, maintainerCount: 1 }, evidence }; } } as never,
    {} as never,
    {} as never,
    {} as never,
    { async lookupEndpoint() { return { checked: false, findings: [] }; }, async lookupPackage() { return { checked: true, findings: [] }; }, async status() { return { available: true, configured: true, activeIndicators: 0, sources: 0 }; } } as never,
    journal
  );
  const assessment = await omni.packageRisk("npm", "fixture", "1.0.0");
  expect(assessment).toMatchObject({ riskScore: 0, recommendation: "proceed", policyVersion: "omni-risk-v1" });
});
