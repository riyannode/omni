import { describe, expect, test } from "bun:test";
import { extractRiskFeatures, RISK_FEATURE_SCHEMA_VERSION } from "../src/domain/risk-features.ts";
import { DEFAULT_RISK_POLICY, RISK_POLICY_VERSION } from "../src/domain/risk-policy.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
import { NoopAssessmentJournal, type AssessmentJournal } from "../src/data/assessment-journal.ts";
import type { RiskSnapshot } from "../src/domain/risk.ts";

const snapshot: RiskSnapshot = {
  subject: { type: "package", id: "npm:demo@1.0.0" },
  vulnerabilities: [], exploitationChecked: true, threatIntelChecked: true, threatFindings: [],
  packageSupplyChain: { registry: "npm", deprecated: true, hasInstallScript: false, integrityPresent: true, signatureCount: 0, maintainerCount: 2 },
  evidence: []
};

describe("learning-ready deterministic boundaries", () => {
  test("default policy and provenance are stable", () => {
    const result = new RiskEngine().assess(snapshot);
    expect(DEFAULT_RISK_POLICY.version).toBe(RISK_POLICY_VERSION);
    expect(result.policyVersion).toBe("omni-risk-v1");
  });

  test("feature extraction is deterministic and contains facts, not scores", () => {
    const first = extractRiskFeatures(snapshot);
    const second = extractRiskFeatures(structuredClone(snapshot));
    expect(first).toEqual(second);
    expect(first.schemaVersion).toBe(RISK_FEATURE_SCHEMA_VERSION);
    expect(first).not.toHaveProperty("riskScore");
    expect(first.package.deprecated).toBe(true);
  });

  test("candidate policy is isolated from the default runtime", () => {
    const candidate = structuredClone(DEFAULT_RISK_POLICY);
    candidate.package.deprecated = 40;
    const baseline = new RiskEngine().assess(snapshot);
    const changed = new RiskEngine(candidate).assess(snapshot);
    expect(changed.riskScore).not.toBe(baseline.riskScore);
    expect(DEFAULT_RISK_POLICY.package.deprecated).toBe(15);
    expect(new RiskEngine().assess(snapshot).riskScore).toBe(baseline.riskScore);
  });

  test("no-op journal does not affect assessment availability without a database", async () => {
    const journal: AssessmentJournal = new NoopAssessmentJournal();
    const id = await journal.record(snapshot, extractRiskFeatures(snapshot), new RiskEngine().assess(snapshot));
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    expect(await journal.loadLabelled()).toEqual([]);
  });
});
