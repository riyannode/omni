export type EvaluationLabel = "benign" | "incident";

export type EvaluationRow = {
  assessment: { riskScore: number };
  label: EvaluationLabel;
};

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

export function featuresEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
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
