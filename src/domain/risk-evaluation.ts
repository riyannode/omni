export type EvaluationLabel = "benign" | "incident";

export type EvaluationRow = {
  assessment: { riskScore: number };
  label: EvaluationLabel;
};

export type SubjectKind = "package" | "repository" | "dependency_set" | "x402_endpoint";

export type ReplayableRow = VersionedSchemaRow & { subjectType: SubjectKind };

// Historical rows whose feature extraction is semantically identical under the
// current extractor: supported non-repository subjects never read repository
// evidence, so replaying them cannot reinterpret historical repository facts.
const SAFE_REPLAY_SUBJECT_KINDS: readonly SubjectKind[] = ["package", "x402_endpoint", "dependency_set"];

function isSafeReplay(row: ReplayableRow, snapshotSchemaVersion: number, featureSchemaVersion: number): boolean {
  if (row.snapshotSchemaVersion === snapshotSchemaVersion && row.featureSchemaVersion === featureSchemaVersion) return true;
  if (row.snapshotSchemaVersion === 3 && row.featureSchemaVersion === 3) return SAFE_REPLAY_SUBJECT_KINDS.includes(row.subjectType);
  if (row.snapshotSchemaVersion === 1 && row.featureSchemaVersion === 1) return SAFE_REPLAY_SUBJECT_KINDS.includes(row.subjectType);
  return false;
}

export type EvaluationMetrics = {
  TP: number;
  FP: number;
  TN: number;
  FN: number;
  precision: number | null;
  recall: number | null;
  falsePositiveRate: number | null;
  falseNegativeRate: number | null;
  falseNegativeCount: number;
};

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(item => item === undefined ? null : canonicalize(item));
  if (value && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const item = (value as Record<string, unknown>)[key];
      if (item !== undefined) result[key] = canonicalize(item);
    }
    return result;
  }
  return value;
}

export type VersionedSchemaRow = { snapshotSchemaVersion: number; featureSchemaVersion: number };

export function partitionCompatibleRows<T extends ReplayableRow>(rows: readonly T[], snapshotSchemaVersion: number, featureSchemaVersion: number): { compatible: T[]; incompatible: T[]; schemaVersionsPresent: { snapshot: number[]; feature: number[] } } {
  const compatible: T[] = []; const incompatible: T[] = [];
  for (const row of rows) (isSafeReplay(row, snapshotSchemaVersion, featureSchemaVersion) ? compatible : incompatible).push(row);
  return { compatible, incompatible, schemaVersionsPresent: { snapshot: [...new Set(rows.map(row => row.snapshotSchemaVersion))].sort((a, b) => a - b), feature: [...new Set(rows.map(row => row.featureSchemaVersion))].sort((a, b) => a - b) } };
}

export function featuresEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
}

// Cohort-aware drift accounting. Schema evolution must not count as feature
// drift: supported historical rows legitimately lack the fields introduced by
// later feature schemas. Project those rows to their shared non-repository
// surface; current-cohort rows remain byte-exact.
export function featuresEqualForCohort(left: unknown, right: unknown, snapshotSchemaVersion: number, subjectType?: SubjectKind): { equal: boolean; comparison: "current-schema" | "legacy-projected" } {
  const canProjectLegacySurface = subjectType === undefined ? snapshotSchemaVersion === 1 : SAFE_REPLAY_SUBJECT_KINDS.includes(subjectType);
  if (snapshotSchemaVersion < 4 && canProjectLegacySurface) {
    return { equal: featuresEqual(projectLegacyFeatures(left), projectLegacyFeatures(right)), comparison: "legacy-projected" };
  }
  return { equal: featuresEqual(left, right), comparison: "current-schema" };
}

function projectLegacyFeatures(value: unknown): unknown {
  if (!value || typeof value !== "object") return value;
  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (key === "schemaVersion" || key === "repository") continue;
    result[key] = canonicalize(item);
  }
  return result;
}

export function evaluateThreshold(rows: readonly EvaluationRow[], threshold: number): EvaluationMetrics {
  let TP = 0, FP = 0, TN = 0, FN = 0;
  for (const row of rows) {
    const predictedIncident = row.assessment.riskScore >= threshold;
    if (predictedIncident && row.label === "incident") TP++;
    else if (predictedIncident) FP++;
    else if (row.label === "incident") FN++;
    else TN++;
  }
  return {
    TP, FP, TN, FN,
    precision: TP + FP === 0 ? null : TP / (TP + FP),
    recall: TP + FN === 0 ? null : TP / (TP + FN),
    falsePositiveRate: FP + TN === 0 ? null : FP / (FP + TN),
    falseNegativeRate: FN + TP === 0 ? null : FN / (FN + TP),
    falseNegativeCount: FN
  };
}
