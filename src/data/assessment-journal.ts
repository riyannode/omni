import { randomUUID } from "node:crypto";
import { SQL } from "bun";
import type { RiskAssessment, RiskSnapshot } from "../domain/risk.ts";
import { RISK_SNAPSHOT_SCHEMA_VERSION } from "../domain/risk.ts";
import type { RiskFeatures } from "../domain/risk-features.ts";
import { RISK_FEATURE_SCHEMA_VERSION } from "../domain/risk-features.ts";

export type AssessmentLabel = "benign" | "incident";
export type AssessmentRecord = {
  assessmentId: string;
  subjectType: RiskSnapshot["subject"]["type"];
  subjectId: string;
  snapshotSchemaVersion: number;
  featureSchemaVersion: number;
  policyVersion: string;
  snapshot: RiskSnapshot;
  features: RiskFeatures;
  assessment: RiskAssessment;
  assessedAt: string;
};
export type LabelledAssessment = AssessmentRecord & { label: AssessmentLabel; source: string; sourceReference?: string; notes?: string; labeledAt: string };

export interface AssessmentJournal {
  record(snapshot: RiskSnapshot, features: RiskFeatures, assessment: RiskAssessment): Promise<string>;
  labelAssessment(assessmentId: string, label: AssessmentLabel, source: string, sourceReference?: string, notes?: string): Promise<void>;
  loadLabelled(): Promise<LabelledAssessment[]>;
}

export class NoopAssessmentJournal implements AssessmentJournal {
  async record(): Promise<string> { return randomUUID(); }
  async labelAssessment(): Promise<void> { throw new Error("assessment journal is not configured"); }
  async loadLabelled(): Promise<LabelledAssessment[]> { return []; }
}

type AssessmentRow = {
  assessment_id: string;
  subject_type: AssessmentRecord["subjectType"];
  subject_id: string;
  snapshot_schema_version: number;
  feature_schema_version: number;
  policy_version: string;
  snapshot: RiskSnapshot | string;
  features: RiskFeatures | string;
  assessment: RiskAssessment | string;
  assessed_at: Date | string;
  label: AssessmentLabel;
  label_source: string;
  source_reference: string | null;
  notes: string | null;
  labeled_at: Date | string;
};

function parseJson<T>(value: T | string): T {
  return typeof value === "string" ? JSON.parse(value) as T : value;
}

class PostgresAssessmentJournal implements AssessmentJournal {
  private readonly db: SQL;
  constructor(url: string) { this.db = new SQL(url, { max: 20, idleTimeout: 30, connectionTimeout: 5 }); }

  async record(snapshot: RiskSnapshot, features: RiskFeatures, assessment: RiskAssessment): Promise<string> {
    const assessmentId = randomUUID();
    await this.db`
      INSERT INTO assessment_records
        (assessment_id, subject_type, subject_id, snapshot_schema_version, feature_schema_version, policy_version, snapshot, features, assessment, assessed_at)
      VALUES
        (${assessmentId}, ${snapshot.subject.type}, ${snapshot.subject.id}, ${RISK_SNAPSHOT_SCHEMA_VERSION}, ${RISK_FEATURE_SCHEMA_VERSION}, ${assessment.policyVersion}, ${JSON.stringify(snapshot)}::jsonb, ${JSON.stringify(features)}::jsonb, ${JSON.stringify(assessment)}::jsonb, ${assessment.assessedAt})
    `;
    return assessmentId;
  }

  async labelAssessment(assessmentId: string, label: AssessmentLabel, source: string, sourceReference?: string, notes?: string): Promise<void> {
    const existing = await this.db<{ assessment_id: string }[]>`SELECT assessment_id FROM assessment_records WHERE assessment_id = ${assessmentId}`;
    if (existing.length === 0) throw new Error(`assessment not found: ${assessmentId}`);
    await this.db`
      INSERT INTO assessment_labels (assessment_id, label, source, source_reference, notes)
      VALUES (${assessmentId}, ${label}, ${source}, ${sourceReference ?? null}, ${notes ?? null})
      ON CONFLICT (assessment_id) DO UPDATE SET label = EXCLUDED.label, source = EXCLUDED.source, source_reference = EXCLUDED.source_reference, notes = EXCLUDED.notes, updated_at = now()
    `;
  }

  async loadLabelled(): Promise<LabelledAssessment[]> {
    const rows = await this.db<AssessmentRow[]>`
      SELECT r.assessment_id, r.subject_type, r.subject_id, r.snapshot_schema_version, r.feature_schema_version, r.policy_version,
             r.snapshot, r.features, r.assessment, r.assessed_at,
             l.label, l.source AS label_source, l.source_reference, l.notes, l.labeled_at
      FROM assessment_records r JOIN assessment_labels l ON l.assessment_id = r.assessment_id
      ORDER BY r.assessed_at ASC
    `;
    return rows.map(row => ({
      assessmentId: row.assessment_id, subjectType: row.subject_type, subjectId: row.subject_id,
      snapshotSchemaVersion: row.snapshot_schema_version, featureSchemaVersion: row.feature_schema_version,
      policyVersion: row.policy_version, snapshot: parseJson(row.snapshot), features: parseJson(row.features), assessment: parseJson(row.assessment),
      assessedAt: new Date(row.assessed_at).toISOString(), label: row.label, source: row.label_source,
      ...(row.source_reference === null ? {} : { sourceReference: row.source_reference }),
      ...(row.notes === null ? {} : { notes: row.notes }), labeledAt: new Date(row.labeled_at).toISOString()
    }));
  }
}

export function createAssessmentJournal(databaseUrl?: string): AssessmentJournal {
  return databaseUrl ? new PostgresAssessmentJournal(databaseUrl) : new NoopAssessmentJournal();
}
