import { readFile } from "node:fs/promises";
import { createAssessmentJournal } from "../src/data/assessment-journal.ts";
import { extractRiskFeatures, RISK_FEATURE_SCHEMA_VERSION } from "../src/domain/risk-features.ts";
import { DEFAULT_RISK_POLICY, type RiskPolicy } from "../src/domain/risk-policy.ts";
import { RISK_SNAPSHOT_SCHEMA_VERSION } from "../src/domain/risk.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";

function exactKeys(value: Record<string, unknown>, keys: string[], path: string) {
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`${path} has invalid shape`);
}
function numberAt(value: unknown, path: string, min = 0, max = 1000): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max) throw new Error(`${path} must be a finite number in [${min}, ${max}]`);
  return value;
}
function validatePolicy(input: unknown): RiskPolicy {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("candidate policy must be an object");
  const p = input as Record<string, unknown>;
  exactKeys(p, ["version", "severityWeights", "severityRanks", "scoreLevelThresholds", "recommendationThresholds", "score", "package", "repository", "threatIntel", "endpoint", "payment"], "policy");
  if (typeof p.version !== "string" || !p.version.trim()) throw new Error("policy.version must be non-empty");
  const groups: Record<string, string[]> = {
    severityWeights: ["unknown", "low", "medium", "high", "critical"], severityRanks: ["unknown", "low", "medium", "high", "critical"],
    scoreLevelThresholds: ["medium", "high", "critical"], recommendationThresholds: ["caution", "manualReview", "doNotProceed"],
    score: ["minimum", "maximum", "sourceErrorPenalty", "sourceErrorPenaltyCap", "zeroCoverageFloor", "partialCoverageFloor"],
    package: ["deprecated", "installScript", "missingIntegrity", "noMaintainer", "knownExploitation"], repository: ["scorecardMaximum", "scorecardRiskMultiplier"],
    threatIntel: ["low", "medium", "high", "critical"], endpoint: ["unlisted", "serverError", "handshakeMissing", "noSupportedPath"],
    payment: ["payToChange", "networkChange", "priceChange", "schemaChange", "providerChange"]
  };
  for (const [group, keys] of Object.entries(groups)) {
    const value = p[group]; if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`policy.${group} must be an object`);
    exactKeys(value as Record<string, unknown>, keys, `policy.${group}`);
    for (const key of keys) numberAt((value as Record<string, unknown>)[key], `policy.${group}.${key}`);
  }
  const score = p.score as Record<string, unknown>;
  if (numberAt(score.minimum, "score.minimum") !== 0 || numberAt(score.maximum, "score.maximum") !== 100) throw new Error("score range must remain 0..100");
  const rec = p.recommendationThresholds as Record<string, unknown>; const level = p.scoreLevelThresholds as Record<string, unknown>;
  if (!(numberAt(rec.caution, "recommendationThresholds.caution") < numberAt(rec.manualReview, "recommendationThresholds.manualReview") && numberAt(rec.manualReview, "recommendationThresholds.manualReview") < numberAt(rec.doNotProceed, "recommendationThresholds.doNotProceed"))) throw new Error("recommendation thresholds must be increasing");
  if (!(numberAt(level.medium, "scoreLevelThresholds.medium") < numberAt(level.high, "scoreLevelThresholds.high") && numberAt(level.high, "scoreLevelThresholds.high") < numberAt(level.critical, "scoreLevelThresholds.critical"))) throw new Error("dimension thresholds must be increasing");
  return structuredClone(input) as RiskPolicy;
}
function normalized(value: unknown): string { return JSON.stringify(value, (_key, item) => item === undefined ? undefined : item); }
function metrics(rows: Awaited<ReturnType<ReturnType<typeof createAssessmentJournal>["loadLabelled"]>>, threshold: number) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const row of rows) { const predicted = row.assessment.riskScore >= threshold; const incident = row.label === "incident"; if (predicted && incident) tp++; else if (predicted) fp++; else if (incident) fn++; else tn++; }
  return { TP: tp, FP: fp, TN: tn, FN: fn, precision: tp + fp === 0 ? null : tp / (tp + fp), recall: tp + fn === 0 ? null : tp / (tp + fn), falsePositiveRate: fp + tn === 0 ? null : fp / (fp + tn), falseNegativeRate: fn + tp === 0 ? null : fn / (fn + tp), falseNegativeCount: fn };
}

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
const candidatePath = process.argv[2];
const policy = candidatePath ? validatePolicy(JSON.parse(await readFile(candidatePath, "utf8"))) : DEFAULT_RISK_POLICY;
const rows = await createAssessmentJournal(process.env.DATABASE_URL).loadLabelled();
const schemaVersions = [...new Set(rows.map(row => row.snapshotSchemaVersion))];
const featureSchemaVersions = [...new Set(rows.map(row => row.featureSchemaVersion))];
if (schemaVersions.some(version => version !== RISK_SNAPSHOT_SCHEMA_VERSION) || featureSchemaVersions.some(version => version !== RISK_FEATURE_SCHEMA_VERSION)) throw new Error(`incompatible schema versions: snapshots=${schemaVersions.join(",")}, features=${featureSchemaVersions.join(",")}`);
const engine = new RiskEngine(policy); let featureDrift = 0;
const replayed = rows.map(row => { const freshFeatures = extractRiskFeatures(row.snapshot); if (normalized(freshFeatures) !== normalized(row.features)) featureDrift++; return { ...row, assessment: engine.assessFeatures(row.snapshot, freshFeatures) }; });
const thresholdReports = { caution: metrics(replayed, policy.recommendationThresholds.caution), manualReview: metrics(replayed, policy.recommendationThresholds.manualReview), doNotProceed: metrics(replayed, policy.recommendationThresholds.doNotProceed) };
console.log(JSON.stringify({ policyVersion: policy.version, dataset: { totalLabelledAssessments: rows.length, benign: rows.filter(row => row.label === "benign").length, incident: rows.filter(row => row.label === "incident").length }, thresholds: thresholdReports, schemaVersions: { snapshot: schemaVersions, feature: featureSchemaVersions }, featureDrift }));
