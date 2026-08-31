import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { SQL } from "bun";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { migrate, validateMigrationFilenames } from "../db/migrate.ts";

const databaseUrl = process.env.MIGRATION_TEST_DATABASE_URL;
const postgresTest = test.if(Boolean(databaseUrl));
let db: SQL | undefined;
let baselineSql = "";

test("rejects numeric-equivalent duplicate migration versions", () => {
  expect(() => validateMigrationFilenames(["001_first.sql", "1_second.sql"])).toThrow("duplicate migration version: 001");
});

beforeAll(async () => {
  if (!databaseUrl) return;
  db = new SQL(databaseUrl);
  await db.unsafe("DROP TABLE IF EXISTS assessment_labels, paid_requests, assessment_records, threat_indicators, endpoint_observations, endpoint_state, schema_migrations CASCADE");
  baselineSql = await readFile(new URL("../db/migrations/001_baseline.sql", import.meta.url), "utf8");
  await db.unsafe(baselineSql);
  await db`INSERT INTO paid_requests (idempotency_key, request_fingerprint, route) VALUES ('11111111-1111-4111-8111-111111111111', 'fixture-paid', 'package')`;
  await db`INSERT INTO endpoint_state (resource, fingerprint) VALUES ('https://fixture.example/', 'fixture-endpoint')`;
  await db`INSERT INTO endpoint_observations (resource, fingerprint) VALUES ('https://fixture.example/', 'fixture-observation')`;
  await db`INSERT INTO assessment_records (assessment_id, subject_type, subject_id, snapshot_schema_version, feature_schema_version, policy_version, snapshot, features, assessment, assessed_at) VALUES ('22222222-2222-4222-8222-222222222222', 'package', 'npm:fixture@1.0.0', 1, 1, 'fixture', '{}', '{}', '{}', now())`;
  await db`INSERT INTO threat_indicators (indicator_type, indicator, threat_type, severity, source) VALUES ('package', 'npm:fixture@1.0.0', 'fixture', 'low', 'fixture')`;
});

afterAll(async () => { await db?.close(); });

describe("native migrations (requires MIGRATION_TEST_DATABASE_URL)", () => {
  postgresTest("baselines legacy schema, applies lifecycle, preserves rows, and reruns as a no-op", async () => {
    if (!databaseUrl || !db) throw new Error("MIGRATION_TEST_DATABASE_URL missing");
    const database = db;
    const result = await migrate(databaseUrl);
    expect(result.applied).toEqual(["001", "002"]);
    const records = await db<{ version: string; checksum: string }[]>`SELECT version, checksum FROM schema_migrations ORDER BY version`;
    expect(records).toHaveLength(2);
    expect(records.map(row => row.version)).toEqual(["001", "002"]);
    const counts = await Promise.all(["paid_requests", "endpoint_state", "endpoint_observations", "assessment_records", "threat_indicators"].map(async table => ({ table_name: table, count: Number((await database.unsafe<{ count: number }[]>(`SELECT count(*)::int AS count FROM ${table}`))[0]!.count) })));
    expect(counts.sort((left, right) => left.table_name.localeCompare(right.table_name))).toEqual([
      { table_name: "assessment_records", count: 1 },
      { table_name: "endpoint_observations", count: 1 },
      { table_name: "endpoint_state", count: 1 },
      { table_name: "paid_requests", count: 1 },
      { table_name: "threat_indicators", count: 1 }
    ]);
    const lifecycle = await db<{ column_name: string; column_default: string | null }[]>`SELECT column_name, column_default FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'threat_indicators' AND column_name = 'lifecycle'`;
    expect(lifecycle).toEqual([{ column_name: "lifecycle", column_default: "'active'::text" }]);
    const active = await db<{ lifecycle: string }[]>`SELECT lifecycle FROM threat_indicators WHERE source = 'fixture'`;
    expect(active).toEqual([{ lifecycle: "active" }]);
    let constraintRejected = false;
    try {
      await db`INSERT INTO threat_indicators (indicator_type, indicator, threat_type, severity, source, lifecycle) VALUES ('url', 'https://invalid.example/', 'phishing', 'critical', 'migration-test', 'invalid')`;
    } catch { constraintRejected = true; }
    expect(constraintRejected).toBe(true);
    const rerun = await migrate(databaseUrl);
    expect(rerun).toEqual({ applied: [], skipped: ["001", "002"] });
  });

  postgresTest("fails closed on checksum mismatch and on legacy schema drift", async () => {
    if (!databaseUrl || !db) throw new Error("MIGRATION_TEST_DATABASE_URL missing");
    const original = await db<{ checksum: string }[]>`SELECT checksum FROM schema_migrations WHERE version = '001'`;
    await db`UPDATE schema_migrations SET checksum = ${"0".repeat(64)} WHERE version = '001'`;
    let checksumRejected = false;
    try { await migrate(databaseUrl); } catch (error) { checksumRejected = error instanceof Error && error.message.includes("checksum mismatch"); }
    expect(checksumRejected).toBe(true);
    await db`UPDATE schema_migrations SET checksum = ${original[0]!.checksum} WHERE version = '001'`;
    await db.unsafe("DROP TABLE IF EXISTS assessment_labels, paid_requests, assessment_records, threat_indicators, endpoint_observations, endpoint_state, schema_migrations CASCADE");
    await db.unsafe(baselineSql);
    await db`ALTER TABLE paid_requests ALTER COLUMN route TYPE varchar(32)`;
    let driftRejected = false;
    try { await migrate(databaseUrl); } catch (error) { driftRejected = error instanceof Error && error.message.includes("baseline column shape mismatch: paid_requests.route"); }
    expect(driftRejected).toBe(true);
    await db.unsafe("DROP TABLE IF EXISTS assessment_labels, paid_requests, assessment_records, threat_indicators, endpoint_observations, endpoint_state, schema_migrations CASCADE");
    await db`CREATE TABLE unrelated_fixture (id integer)`;
    const fresh = await migrate(databaseUrl);
    expect(fresh).toEqual({ applied: ["001", "002"], skipped: [] });
    await db`ALTER TABLE threat_indicators ALTER COLUMN lifecycle DROP DEFAULT`;
    let lifecycleRejected = false;
    try { await migrate(databaseUrl); } catch (error) { lifecycleRejected = error instanceof Error && error.message.includes("lifecycle schema invalid"); }
    expect(lifecycleRejected).toBe(true);
  });

  postgresTest("canonicalizes a persisted numeric migration version alias", async () => {
    if (!databaseUrl || !db) throw new Error("MIGRATION_TEST_DATABASE_URL missing");
    await db.unsafe("DROP TABLE IF EXISTS assessment_labels, paid_requests, assessment_records, threat_indicators, endpoint_observations, endpoint_state, schema_migrations CASCADE");
    await db.unsafe(baselineSql);
    const baselineChecksum = createHash("sha256").update(baselineSql).digest("hex");
    await db`CREATE TABLE schema_migrations (version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`;
    await db`INSERT INTO schema_migrations (version, checksum) VALUES ('1', ${baselineChecksum})`;
    const result = await migrate(databaseUrl);
    expect(result).toEqual({ applied: ["002"], skipped: ["001"] });
    const records = await db<{ version: string }[]>`SELECT version FROM schema_migrations ORDER BY version`;
    expect(records.map(row => row.version)).toEqual(["001", "002"]);
  });
});
