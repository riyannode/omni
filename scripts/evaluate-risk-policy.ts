import { readFile } from "node:fs/promises";
import { createAssessmentJournal } from "../src/data/assessment-journal.ts";
import { extractRiskFeatures, RISK_FEATURE_SCHEMA_VERSION } from "../src/domain/risk-features.ts";
import { DEFAULT_RISK_POLICY, type RiskPolicy } from "../src/domain/risk-policy.ts";
import { RISK_SNAPSHOT_SCHEMA_VERSION } from "../src/domain/risk.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
import { evaluateThreshold, featuresEqual, featuresEqualForCohort, partitionCompatibleRows, type EvaluationRow } from "../src/domain/risk-evaluation.ts";

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

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
const candidatePath = process.argv[2];
const policy = candidatePath ? validatePolicy(JSON.parse(await readFile(candidatePath, "utf8"))) : DEFAULT_RISK_POLICY;
const rows = await createAssessmentJournal(process.env.DATABASE_URL).loadLabelled();
// Replay compatibility: current-cohort rows always evaluate. Historical v1
// package/x402/dependency_set rows are replayed because their feature extraction is
// semantically unchanged (repositoryEvidence did not exist in v1 and is never read for
// these subject kinds). v1 repository rows stay incompatible: replaying them under the
// v2 extractor would reinterpret historical repository evidence with new optional
// fields, so they are reported as skipped instead of silently re-scored.
const cohorts = partitionCompatibleRows(rows, RISK_SNAPSHOT_SCHEMA_VERSION, RISK_FEATURE_SCHEMA_VERSION);
const engine = new RiskEngine(policy); let currentSchemaDrift = 0; let legacySchemaDrift = 0;
const replayed = cohorts.compatible.map(row => {
  const freshFeatures = extractRiskFeatures(row.snapshot);
  const drift = featuresEqualForCohort(freshFeatures, row.features, row.snapshotSchemaVersion);
  if (!drift.equal) { if (drift.comparison === "current-schema") currentSchemaDrift++; else legacySchemaDrift++; }
  return { ...row, assessment: engine.assessFeatures(row.snapshot, freshFeatures) };
});
const thresholdReports = { caution: evaluateThreshold(replayed, policy.recommendationThresholds.caution), manualReview: evaluateThreshold(replayed, policy.recommendationThresholds.manualReview), doNotProceed: evaluateThreshold(replayed, policy.recommendationThresholds.doNotProceed) };
console.log(JSON.stringify({ policyVersion: policy.version, dataset: { totalLabelledAssessments: rows.length, compatibleRowsEvaluated: cohorts.compatible.length, incompatibleOrOlderRowsSkipped: cohorts.incompatible.length, benign: replayed.filter(row => row.label === "benign").length, incident: replayed.filter(row => row.label === "incident").length }, thresholds: thresholdReports, schemaVersionsPresent: cohorts.schemaVersionsPresent, compatibleSchema: { snapshot: RISK_SNAPSHOT_SCHEMA_VERSION, feature: RISK_FEATURE_SCHEMA_VERSION }, featureDrift: { currentSchemaByteComparisonDrift: currentSchemaDrift, legacyProjectedSemanticDrift: legacySchemaDrift } }));
