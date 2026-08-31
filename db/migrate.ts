import { SQL } from "bun";
import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";

const ADVISORY_LOCK_KEY = "omni:schema-migrations";
const BASELINE_VERSION = "001";
const BASELINE_TABLES = ["endpoint_state", "endpoint_observations", "threat_indicators", "assessment_records", "paid_requests", "assessment_labels"] as const;
const BASELINE_COLUMNS: Record<typeof BASELINE_TABLES[number], readonly string[]> = {
  endpoint_state: ["resource", "fingerprint", "first_seen_at", "last_seen_at"],
  endpoint_observations: ["id", "resource", "fingerprint", "provider_name", "pay_to", "method", "price_atomic", "network", "schema_hash", "supports_gateway", "supports_vanilla", "observed_at"],
  threat_indicators: ["id", "indicator_type", "indicator", "threat_type", "severity", "source", "source_reference", "first_seen_at", "last_seen_at", "expires_at"],
  assessment_records: ["assessment_id", "subject_type", "subject_id", "snapshot_schema_version", "feature_schema_version", "policy_version", "snapshot", "features", "assessment", "assessed_at"],
  paid_requests: ["idempotency_key", "request_fingerprint", "route", "state", "payment_nonce", "circle_transfer_id", "payer", "network", "pay_to", "asset", "amount_atomic", "final_result", "final_status", "created_at", "updated_at", "execution_lease_at", "execution_lease_id"],
  assessment_labels: ["assessment_id", "label", "source", "source_reference", "notes", "labeled_at", "updated_at"]
};

type Migration = { version: string; filename: string; sql: string; checksum: string };
type MigrationRow = { version: string; checksum: string };
type TableColumnRow = { table_name: string; column_name: string };
type ConstraintRow = { table_name: string; constraint_type: string; definition: string };

function checksum(sql: string): string { return createHash("sha256").update(sql).digest("hex"); }
function sqlList(values: readonly string[]): string { return values.map(value => `'${value}'`).join(", "); }

async function loadMigrations(): Promise<Migration[]> {
  const directory = new URL("./migrations/", import.meta.url);
  const filenames = (await readdir(directory)).filter(filename => /^\d+_[a-z0-9_-]+\.sql$/.test(filename)).sort((left, right) => left.localeCompare(right));
  const migrations = await Promise.all(filenames.map(async filename => {
    const version = filename.match(/^(\d+)_/)?.[1];
    if (!version) throw new Error(`invalid migration filename: ${filename}`);
    const sql = await readFile(new URL(filename, directory), "utf8");
    return { version, filename, sql, checksum: checksum(sql) };
  }));
  const versions = new Set<string>();
  for (const migration of migrations) {
    if (versions.has(migration.version)) throw new Error(`duplicate migration version: ${migration.version}`);
    versions.add(migration.version);
  }
  return migrations;
}

async function verifyLegacyBaseline(tx: SQL): Promise<void> {
  const tableRows = await tx.unsafe<TableColumnRow[]>(`
    SELECT table_name, column_name
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name IN (${sqlList(BASELINE_TABLES)})
  `);
  const columnsByTable = new Map<string, Set<string>>();
  for (const row of tableRows) {
    const columns = columnsByTable.get(row.table_name) ?? new Set<string>();
    columns.add(row.column_name);
    columnsByTable.set(row.table_name, columns);
  }
  for (const table of BASELINE_TABLES) {
    const columns = columnsByTable.get(table);
    if (!columns) throw new Error(`legacy database is missing baseline table: ${table}`);
    for (const column of BASELINE_COLUMNS[table]) if (!columns.has(column)) throw new Error(`legacy database is missing baseline column: ${table}.${column}`);
  }

  const constraints = await tx.unsafe<ConstraintRow[]>(`
    SELECT pg_class.relname AS table_name, CASE contype WHEN 'p' THEN 'primary_key' WHEN 'u' THEN 'unique' WHEN 'c' THEN 'check' WHEN 'f' THEN 'foreign_key' END AS constraint_type, pg_get_constraintdef(pg_constraint.oid) AS definition
    FROM pg_constraint
    JOIN pg_class ON pg_class.oid = pg_constraint.conrelid
    JOIN pg_namespace ON pg_namespace.oid = pg_class.relnamespace
    WHERE pg_namespace.nspname = 'public' AND pg_class.relname IN (${sqlList(BASELINE_TABLES)})
  `);
  const has = (table: string, type: string, fragment: string): boolean => constraints.some(row => row.table_name === table && row.constraint_type === type && row.definition.toLowerCase().replaceAll('"', "").includes(fragment.toLowerCase()));
  const requiredConstraints: Array<[string, string, string]> = [
    ["endpoint_state", "primary_key", "primary key (resource)"],
    ["endpoint_observations", "primary_key", "primary key (id)"],
    ["threat_indicators", "primary_key", "primary key (id)"],
    ["threat_indicators", "unique", "unique (indicator_type, indicator, threat_type, source)"],
    ["threat_indicators", "check", "indicator_type = any"],
    ["threat_indicators", "check", "severity = any"],
    ["assessment_records", "primary_key", "primary key (assessment_id)"],
    ["paid_requests", "primary_key", "primary key (idempotency_key)"],
    ["paid_requests", "check", "state = any"],
    ["paid_requests", "check", "final_status >="],
    ["assessment_labels", "primary_key", "primary key (assessment_id)"],
    ["assessment_labels", "foreign_key", "foreign key (assessment_id) references assessment_records"]
  ];
  for (const [table, type, fragment] of requiredConstraints) if (!has(table, type, fragment)) throw new Error(`legacy database baseline constraint missing: ${table} ${type} ${fragment}`);
}

async function hasUserTables(tx: SQL): Promise<boolean> {
  const rows = await tx<{ table_name: string }[]>`
    SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE' AND table_name <> 'schema_migrations'
    LIMIT 1
  `;
  return rows.length > 0;
}

async function transaction<T>(connection: SQL, operation: (tx: SQL) => Promise<T>): Promise<T> {
  await connection`BEGIN`;
  try {
    const result = await operation(connection);
    await connection`COMMIT`;
    return result;
  } catch (error) {
    try { await connection`ROLLBACK`; } catch {}
    throw error;
  }
}

export async function migrate(databaseUrl: string): Promise<{ applied: string[]; skipped: string[] }> {
  const migrations = await loadMigrations();
  const db = new SQL(databaseUrl, { max: 1, idleTimeout: 30, connectionTimeout: 5 });
  const connection = await db.reserve();
  let locked = false;
  try {
    await connection`SELECT pg_advisory_lock(hashtextextended(${ADVISORY_LOCK_KEY}, 0))`;
    locked = true;
    await transaction(connection, async tx => {
      await tx`CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`;
    });
    const applied: string[] = [];
    const skipped: string[] = [];
    for (const migration of migrations) {
      const result = await transaction(connection, async tx => {
        const rows = await tx<MigrationRow[]>`SELECT version, checksum FROM schema_migrations WHERE version = ${migration.version}`;
        const existing = rows[0];
        if (existing) {
          if (existing.checksum !== migration.checksum) throw new Error(`migration checksum mismatch: ${migration.version}`);
          return "skipped" as const;
        }
        if (migration.version === BASELINE_VERSION && await hasUserTables(tx)) await verifyLegacyBaseline(tx);
        else await tx.unsafe(migration.sql);
        await tx`INSERT INTO schema_migrations (version, checksum) VALUES (${migration.version}, ${migration.checksum})`;
        return "applied" as const;
      });
      (result === "applied" ? applied : skipped).push(migration.version);
    }
    return { applied, skipped };
  } finally {
    if (locked) {
      try { await connection`SELECT pg_advisory_unlock(hashtextextended(${ADVISORY_LOCK_KEY}, 0))`; } catch {}
    }
    connection.release();
    await db.close();
  }
}
