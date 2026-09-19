import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { SQL } from "bun";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createAssessmentJournal } from "../src/data/assessment-journal.ts";
import { extractRiskFeatures } from "../src/domain/risk-features.ts";
import { RISK_SNAPSHOT_SCHEMA_VERSION, type RiskSnapshot } from "../src/domain/risk.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";

const databaseUrl = process.env.TEST_DATABASE_URL;
const postgresTest = test.if(Boolean(databaseUrl));
let setupDb: SQL | undefined;
let journalSetupDb: SQL | undefined;
let isolatedSchema = "";

beforeAll(async () => {
  if (!databaseUrl) return;
  isolatedSchema = `omni_agent_${randomUUID().replaceAll("-", "")}`;
  setupDb = new SQL(databaseUrl, { max: 1, idleTimeout: 30, connectionTimeout: 5 });
  await setupDb.unsafe(`CREATE SCHEMA ${isolatedSchema}`);
  await setupDb.unsafe(`SET search_path TO ${isolatedSchema}`);
  await setupDb.unsafe(await readFile(new URL("../db/schema.sql", import.meta.url), "utf8"));
  journalSetupDb = new SQL(databaseUrl, { max: 1, idleTimeout: 30, connectionTimeout: 5 });
  await journalSetupDb.unsafe(await readFile(new URL("../db/schema.sql", import.meta.url), "utf8"));
});

afterAll(async () => {
  if (setupDb && isolatedSchema) {
    await setupDb.unsafe(`DROP SCHEMA IF EXISTS ${isolatedSchema} CASCADE`);
  }
  await journalSetupDb?.close();
  await setupDb?.close();
});

describe("PostgreSQL agent subject schema and journal (CI TEST_DATABASE_URL)", () => {
  postgresTest("verifies fresh schema, migration preservation/idempotence, and agent journal readback", async () => {
    if (!databaseUrl || !setupDb) throw new Error("TEST_DATABASE_URL missing");

    const freshAgentId = randomUUID();

    await setupDb`
      INSERT INTO assessment_records
        (assessment_id, subject_type, subject_id, snapshot_schema_version, feature_schema_version, policy_version, snapshot, features, assessment, assessed_at)
      VALUES
        (${freshAgentId}, 'agent', 'eip155:1:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42', 5, 5, 'omni-agent-risk-v1', '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, now())
    `;
    const freshRows = await setupDb<{ subject_type: string }[]>`SELECT subject_type FROM assessment_records WHERE assessment_id = ${freshAgentId}`;

    expect(freshRows).toEqual([{ subject_type: "agent" }]);
    await setupDb`DELETE FROM assessment_records WHERE assessment_id = ${freshAgentId}`;

    await setupDb.unsafe("ALTER TABLE assessment_records DROP CONSTRAINT IF EXISTS assessment_records_subject_type_check");
    await setupDb.unsafe("ALTER TABLE assessment_records ADD CONSTRAINT assessment_records_subject_type_check CHECK (subject_type IN ('package', 'repository', 'dependency_set', 'x402_endpoint'))");

    const legacyIds = [randomUUID(), randomUUID(), randomUUID(), randomUUID()];
    for (const [id, subjectType] of legacyIds.map((id, index) => [id, ["package", "repository", "dependency_set", "x402_endpoint"][index] as string])) {

      await setupDb`
        INSERT INTO assessment_records
          (assessment_id, subject_type, subject_id, snapshot_schema_version, feature_schema_version, policy_version, snapshot, features, assessment, assessed_at)
        VALUES
          (${id}, ${subjectType}, ${subjectType + ":fixture"}, 4, 4, 'omni-risk-v3', '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, now())
      `;

    }
    let preMigrationAgentRejected = false;
    try {
      await setupDb`
        INSERT INTO assessment_records
          (assessment_id, subject_type, subject_id, snapshot_schema_version, feature_schema_version, policy_version, snapshot, features, assessment, assessed_at)
        VALUES
          (${randomUUID()}, 'agent', 'pre-migration-agent', 4, 4, 'omni-risk-v3', '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, now())
      `;
    } catch {
      preMigrationAgentRejected = true;
    }
    expect(preMigrationAgentRejected).toBe(true);

    const migration = await readFile(new URL("../db/migrations/001_agent_subject.sql", import.meta.url), "utf8");
    await setupDb.unsafe(migration);
    await setupDb.unsafe(migration);
    const preserved = await setupDb<{ subject_type: string; subject_id: string }[]>`
      SELECT subject_type, subject_id FROM assessment_records WHERE subject_id LIKE '%:fixture' ORDER BY subject_type
    `;
    expect(preserved).toHaveLength(4);
    await setupDb`
      INSERT INTO assessment_records
        (assessment_id, subject_type, subject_id, snapshot_schema_version, feature_schema_version, policy_version, snapshot, features, assessment, assessed_at)
      VALUES
        (${randomUUID()}, 'agent', 'post-migration-agent', 5, 5, 'omni-agent-risk-v1', '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, now())
    `;
    const constraint = await setupDb<{ definition: string }[]>`
      SELECT pg_get_constraintdef(oid) AS definition
      FROM pg_constraint
      WHERE conname = 'assessment_records_subject_type_check'
    `;
    expect(constraint[0]?.definition).toContain("agent");


    const journal = createAssessmentJournal(databaseUrl);
    const snapshot: RiskSnapshot = {
      subject: { type: "agent", id: "eip155:1:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42" },
      evidence: [{ source: "test", kind: "agent_identity", observedAt: "2026-01-01T00:00:00.000Z", detail: { status: "REGISTERED" } }],
      coverage: { modelVersion: "agent-coverage-v1", sources: [{ source: "ERC-8004 Identity Registry", execution: "QUERIED", status: "OBSERVED", weight: 1 }] },
    };
    const features = extractRiskFeatures(snapshot);
    const assessment = new RiskEngine().assess(snapshot);
    const assessmentId = await journal.record(snapshot, features, assessment);

    await journal.labelAssessment(assessmentId, "benign", "postgres-agent-fixture");
    const rows = await journal.loadLabelled();
    const row = rows.find(item => item.assessmentId === assessmentId);
    expect(row).toMatchObject({ subjectType: "agent", snapshotSchemaVersion: RISK_SNAPSHOT_SCHEMA_VERSION, policyVersion: "omni-agent-risk-v1" });
  });
});
