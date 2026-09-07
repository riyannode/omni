import { SQL } from "bun";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { createThreatIntelStore } from "../src/data/threat-intel.ts";

const databaseUrl = process.env.TEST_DATABASE_URL;
const postgresTest = test.if(Boolean(databaseUrl));
const fixtureSource = "scope-regression-fixture";
const fixtureUrl = "https://scope-regression-fixture.example/pay";
const fixtureHostname = "scope-regression-fixture.example";
let setupDb: SQL | undefined;

beforeAll(async () => {
  if (!databaseUrl) return;
  setupDb = new SQL(databaseUrl);
  await setupDb.unsafe(await readFile(new URL("../db/schema.sql", import.meta.url), "utf8"));
  await setupDb`DELETE FROM threat_indicators WHERE source = ${fixtureSource}`;
  await setupDb`
    INSERT INTO threat_indicators (indicator_type, indicator, threat_type, severity, source, source_reference)
    VALUES
      ('url', ${fixtureUrl}, 'scope-fixture-url', 'medium', ${fixtureSource}, 'https://scope-regression-fixture.example/url'),
      ('hostname', ${fixtureHostname}, 'scope-fixture-hostname', 'high', ${fixtureSource}, 'https://scope-regression-fixture.example/hostname')
    ON CONFLICT (indicator_type, indicator, threat_type, source) DO UPDATE SET
      severity = EXCLUDED.severity,
      source_reference = EXCLUDED.source_reference,
      last_seen_at = now(),
      expires_at = NULL
  `;
});

afterAll(async () => {
  if (setupDb) {
    await setupDb`DELETE FROM threat_indicators WHERE source = ${fixtureSource}`;
    await setupDb.close();
  }
});

describe("ThreatIntelStore evidence scopes", () => {
  postgresTest("does not report package coverage from URL/hostname-only indicators", async () => {
    if (!databaseUrl) throw new Error("TEST_DATABASE_URL missing");
    const store = createThreatIntelStore(databaseUrl);

    await expect(store.lookupPackage("npm", "pnpm", "10.28.1")).resolves.toEqual({ checked: false, findings: [] });
    await expect(store.lookupEndpoint(fixtureUrl)).resolves.toMatchObject({ checked: true });
  });
});
