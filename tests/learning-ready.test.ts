import { describe, expect, test } from "bun:test";
import { extractRiskFeatures, RISK_FEATURE_SCHEMA_VERSION } from "../src/domain/risk-features.ts";
import { DEFAULT_RISK_POLICY, RISK_POLICY_VERSION, type RiskPolicy } from "../src/domain/risk-policy.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
import { NoopAssessmentJournal, type AssessmentJournal } from "../src/data/assessment-journal.ts";
import type { RiskSnapshot } from "../src/domain/risk.ts";
import { evaluateThreshold, featuresEqual, type EvaluationRow } from "../src/domain/risk-evaluation.ts";

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

  test("default policy is deeply immutable", () => {
    expect(Object.isFrozen(DEFAULT_RISK_POLICY)).toBe(true);
    expect(Object.isFrozen(DEFAULT_RISK_POLICY.package)).toBe(true);
    expect(() => {
      (DEFAULT_RISK_POLICY as unknown as { package: { deprecated: number } }).package.deprecated = 40;
    }).toThrow();
    expect(DEFAULT_RISK_POLICY.package.deprecated).toBe(15);
  });

  test("feature extraction is deterministic and contains facts, not scores", () => {
    const first = extractRiskFeatures(snapshot);
    const second = extractRiskFeatures(structuredClone(snapshot));
    expect(first).toEqual(second);
    expect(first.schemaVersion).toBe(RISK_FEATURE_SCHEMA_VERSION);
    expect(first).not.toHaveProperty("riskScore");
    expect(first.package.deprecated).toBe(true);
  });

  test("feature drift equality ignores object-key ordering but preserves array ordering", () => {
    expect(featuresEqual({ a: 1, b: { c: 2, d: 3 } }, { b: { d: 3, c: 2 }, a: 1 })).toBe(true);
    expect(featuresEqual({ values: [1, 2] }, { values: [2, 1] })).toBe(false);
  });

  test("feature extraction covers package, repository, and x402 subjects", () => {
    const packageFeatures = extractRiskFeatures(snapshot);
    const repositoryFeatures = extractRiskFeatures({ subject: { type: "repository", id: "github.com/a/b" }, scorecard: 9.5, evidence: [{ source: "Scorecard", kind: "score", observedAt: "2026-01-01T00:00:00.000Z", detail: { score: 9.5 } }] });
    const endpointFeatures = extractRiskFeatures({ subject: { type: "x402_endpoint", id: "https://example.com/pay" }, endpoint: { listedOnCircle: true, supportsGateway: true, supportsVanilla: false, responseStatus: 402 }, activeProbeChecked: true, historyChecked: true, endpointHistory: { observationCount: 1, payToChangeCount: 0, networkChangeCount: 0, priceChangeCount: 0, schemaChangeCount: 0, providerChangeCount: 0, relatedResourcesByPayTo: 0 }, threatIntelChecked: true, threatFindings: [], evidence: [] });
    expect(packageFeatures.package).toMatchObject({ present: true, deprecated: true, integrityPresent: true });
    expect(repositoryFeatures).toMatchObject({ subject: { type: "repository" }, scorecard: 9.5, coverage: { completed: 1, expected: 1 } });
    expect(endpointFeatures.endpoint).toMatchObject({ present: true, listedOnCircle: true, supportsGateway: true, responseStatus: 402 });
  });

  test("candidate policy is isolated from the default runtime", () => {
    const candidate = structuredClone(DEFAULT_RISK_POLICY) as RiskPolicy;
    candidate.package.deprecated = 40;
    const baseline = new RiskEngine().assess(snapshot);
    const changed = new RiskEngine(candidate).assess(snapshot);
    expect(changed.riskScore).not.toBe(baseline.riskScore);
    expect(DEFAULT_RISK_POLICY.package.deprecated).toBe(15);
    expect(new RiskEngine().assess(snapshot).riskScore).toBe(baseline.riskScore);
  });

  test("default policy preserves the existing score and recommendation fixtures", () => {
    const cases: Array<[RiskSnapshot, number, string]> = [
      [{ subject: { type: "package", id: "npm:demo@1.0.0" }, vulnerabilities: [{ id: "CVE-1", severity: "critical", knownExploited: true, aliases: [] }], exploitationChecked: true, evidence: [] }, 90, "do_not_proceed"],
      [{ subject: { type: "package", id: "npm:demo@1.0.0" }, vulnerabilities: [{ id: "GHSA-1", severity: "high", knownExploited: false, aliases: [] }], exploitationChecked: true, evidence: [] }, 60, "manual_review"],
      [{ subject: { type: "repository", id: "github.com/a/b" }, evidence: [], sourceErrors: ["source down"] }, 50, "manual_review"],
      [{ subject: { type: "package", id: "npm:demo@1.0.0" }, vulnerabilities: [{ id: "GHSA-unknown", severity: "unknown", knownExploited: false, aliases: [] }], exploitationChecked: true, evidence: [] }, 30, "proceed_with_caution"],
      [{ subject: { type: "x402_endpoint", id: "https://example.com/paid" }, endpoint: { listedOnCircle: false, responseStatus: 402 }, evidence: [] }, 25, "proceed_with_caution"],
      [{ subject: { type: "repository", id: "github.com/a/b" }, scorecard: 9.5, evidence: [] }, 3, "proceed"],
      [{ subject: { type: "x402_endpoint", id: "https://bad.example/pay" }, endpoint: { listedOnCircle: true, responseStatus: 402 }, activeProbeChecked: true, historyChecked: true, endpointHistory: { observationCount: 2, payToChangeCount: 0, priceChangeCount: 0, networkChangeCount: 0, schemaChangeCount: 0, providerChangeCount: 0, relatedResourcesByPayTo: 0 }, threatIntelChecked: true, threatFindings: [{ indicatorType: "hostname", indicator: "bad.example", threatType: "malware", severity: "critical", source: "licensed-feed" }], evidence: [] }, 100, "do_not_proceed"]
    ];
    for (const [input, score, recommendation] of cases) expect(new RiskEngine().assess(input)).toMatchObject({ riskScore: score, recommendation });
  });

  test("evaluation metrics fixture covers TP, FP, TN, FN and rates", () => {
    const rows: EvaluationRow[] = [
      { assessment: { riskScore: 80 }, label: "incident" }, { assessment: { riskScore: 80 }, label: "benign" },
      { assessment: { riskScore: 10 }, label: "benign" }, { assessment: { riskScore: 10 }, label: "incident" }
    ];
    expect(evaluateThreshold(rows, 50)).toEqual({ TP: 1, FP: 1, TN: 1, FN: 1, precision: 0.5, recall: 0.5, falsePositiveRate: 0.5, falseNegativeRate: 0.5, falseNegativeCount: 1 });
  });

  test("evaluation metrics preserve nulls for zero denominators", () => {
    expect(evaluateThreshold([{ assessment: { riskScore: 10 }, label: "benign" }, { assessment: { riskScore: 10 }, label: "incident" }], 50)).toEqual({ TP: 0, FP: 0, TN: 1, FN: 1, precision: null, recall: 0, falsePositiveRate: 0, falseNegativeRate: 1, falseNegativeCount: 1 });
    expect(evaluateThreshold([{ assessment: { riskScore: 80 }, label: "benign" }], 50)).toEqual({ TP: 0, FP: 1, TN: 0, FN: 0, precision: 0, recall: null, falsePositiveRate: 1, falseNegativeRate: null, falseNegativeCount: 0 });
  });

  test("no-op journal does not affect assessment availability without a database", async () => {
    const journal: AssessmentJournal = new NoopAssessmentJournal();
    const id = await journal.record(snapshot, extractRiskFeatures(snapshot), new RiskEngine().assess(snapshot));
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    expect(await journal.loadLabelled()).toEqual([]);
  });
});
