import { SQL } from "bun";
import { beforeAll, afterAll, describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { createAssessmentJournal } from "../src/data/assessment-journal.ts";
import { extractRiskFeatures, RISK_FEATURE_SCHEMA_VERSION } from "../src/domain/risk-features.ts";
import { RISK_SNAPSHOT_SCHEMA_VERSION, type RiskSnapshot } from "../src/domain/risk.ts";
import { RISK_POLICY_VERSION } from "../src/domain/risk-policy.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";

const databaseUrl = process.env.DATABASE_URL;
const postgresTest = test.if(Boolean(databaseUrl));
const snapshot: RiskSnapshot = {
  subject: { type: "package", id: "npm:journal-fixture@1.0.0" },
  vulnerabilities: [], exploitationChecked: true, threatIntelChecked: true, threatFindings: [],
  packageSupplyChain: { registry: "npm", deprecated: false, hasInstallScript: false, integrityPresent: true, signatureCount: 0, maintainerCount: 1 },
  evidence: [{ source: "test", kind: "journal_fixture", observedAt: "2026-01-01T00:00:00.000Z", detail: { persisted: true } }]
};
let setupDb: SQL | undefined;

beforeAll(async () => {
  if (!databaseUrl) return;
  setupDb = new SQL(databaseUrl);
  await setupDb.unsafe(await readFile(new URL("../db/schema.sql", import.meta.url), "utf8"));
});

afterAll(async () => {
  await setupDb?.close();
});

describe("Postgres assessment journal", () => {
  postgresTest("round-trips the persisted snapshot, features, schema versions, policy, and assessment", async () => {
    const journal = createAssessmentJournal(databaseUrl);
    const features = extractRiskFeatures(snapshot);
    const assessment = new RiskEngine().assess(snapshot);
    const assessmentId = await journal.record(snapshot, features, assessment);
    await journal.labelAssessment(assessmentId, "incident", "incident-report", "https://example.test/report", "verified fixture");
    const [row] = await journal.loadLabelled();
    expect(row).toMatchObject({ assessmentId, subjectType: "package", subjectId: snapshot.subject.id, snapshotSchemaVersion: RISK_SNAPSHOT_SCHEMA_VERSION, featureSchemaVersion: RISK_FEATURE_SCHEMA_VERSION, policyVersion: RISK_POLICY_VERSION, snapshot, features, assessment, label: "incident", source: "incident-report", sourceReference: "https://example.test/report", notes: "verified fixture" });
    expect(row?.assessedAt).toBe(assessment.assessedAt);
  });

  postgresTest("rejects nonexistent assessments and updates label provenance", async () => {
    const journal = createAssessmentJournal(databaseUrl);
    await expect(journal.labelAssessment("00000000-0000-0000-0000-000000000000", "benign", "operator")).rejects.toThrow("assessment not found");
    const assessment = new RiskEngine().assess(snapshot);
    const id = await journal.record(snapshot, extractRiskFeatures(snapshot), assessment);
    await journal.labelAssessment(id, "benign", "initial-review", "case://one", "first pass");
    await journal.labelAssessment(id, "incident", "postmortem", "case://two", "updated finding");
    const rows = await journal.loadLabelled();
    const row = rows.find(item => item.assessmentId === id);
    expect(row).toMatchObject({ label: "incident", source: "postmortem", sourceReference: "case://two", notes: "updated finding" });
  });
});
