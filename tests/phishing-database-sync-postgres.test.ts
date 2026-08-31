import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { SQL } from "bun";
import { createHash } from "node:crypto";
import { createThreatIntelStore } from "../src/data/threat-intel.ts";
import { PHISHING_DATABASE_CHECKSUM_SOURCES, syncPhishingDatabase, reconcilePhishingDatabaseSnapshot } from "../src/providers/phishing-database-sync.ts";
import type { PhishingDatabaseIndicator } from "../src/providers/phishing-database.ts";

const databaseUrl = process.env.THREAT_TEST_DATABASE_URL;
const postgresTest = test.if(Boolean(databaseUrl));
let db: SQL | undefined;
const urlSource = "https://phish.co.za/latest/phishing-links-ACTIVE.txt";
const hostnameSource = "https://phish.co.za/latest/phishing-domains-ACTIVE.txt";
function row(indicatorType: "url" | "hostname", indicator: string, reference: string): PhishingDatabaseIndicator {
  return { indicatorType, indicator, threatType: "phishing", severity: "critical", source: "phishing_database", reference };
}
function checksum(bytes: Uint8Array, filename: string): Uint8Array {
  return new TextEncoder().encode(`${createHash("sha256").update(bytes).digest("hex")} *${filename}\n`);
}
function feedResponses(urlFeed: Uint8Array, hostnameFeed: Uint8Array, invalidHostnameChecksum = false): Map<string, Uint8Array> {
  return new Map([
    ["https://phish.co.za/latest/phishing-links-ACTIVE.txt", urlFeed],
    [PHISHING_DATABASE_CHECKSUM_SOURCES.url, checksum(urlFeed, "phishing-links-ACTIVE.txt")],
    ["https://phish.co.za/latest/phishing-domains-ACTIVE.txt", hostnameFeed],
    [PHISHING_DATABASE_CHECKSUM_SOURCES.hostname, invalidHostnameChecksum ? new TextEncoder().encode(`${"0".repeat(64)} *phishing-domains-ACTIVE.txt\n`) : checksum(hostnameFeed, "phishing-domains-ACTIVE.txt")]
  ]);
}

beforeAll(async () => {
  if (!databaseUrl) return;
  db = new SQL(databaseUrl);
  await db.unsafe("DROP TABLE IF EXISTS assessment_labels, paid_requests, assessment_records, threat_indicators, endpoint_observations, endpoint_state, schema_migrations CASCADE");
  const { readFile } = await import("node:fs/promises");
  await db.unsafe(await readFile(new URL("../db/schema.sql", import.meta.url), "utf8"));
});
afterAll(async () => { await db?.close(); });
beforeEach(async () => { if (db) await db`DELETE FROM threat_indicators WHERE source = 'phishing_database'`; });

describe("Phishing.Database scoped reconciliation (requires THREAT_TEST_DATABASE_URL)", () => {
  postgresTest("keeps URL and hostname snapshots independent, refreshes expiry, and ignores expired rows", async () => {
    if (!databaseUrl || !db) throw new Error("THREAT_TEST_DATABASE_URL missing");
    const firstExpiry = "2026-09-01T00:00:00.000Z";
    const secondExpiry = "2026-09-02T00:00:00.000Z";
    await db.begin(async tx => {
      await reconcilePhishingDatabaseSnapshot(tx, [row("url", "https://shared.example/retained", urlSource), row("url", "https://shared.example/removed", urlSource)], "url", firstExpiry);
      await reconcilePhishingDatabaseSnapshot(tx, [row("hostname", "shared.example", hostnameSource)], "hostname", firstExpiry);
    });
    await db.begin(async tx => {
      await reconcilePhishingDatabaseSnapshot(tx, [row("url", "https://shared.example/retained", urlSource), row("url", "https://new.example/", urlSource)], "url", secondExpiry);
    });
    const rows = await db<{ indicator: string; indicator_type: string; lifecycle: string; expires_at: string }[]>`SELECT indicator, indicator_type, lifecycle, expires_at::text FROM threat_indicators WHERE source = 'phishing_database' ORDER BY indicator`;
    expect(rows).toHaveLength(4);
    expect(rows).toEqual(expect.arrayContaining([
      { indicator: "https://new.example/", indicator_type: "url", lifecycle: "active", expires_at: expect.any(String) },
      { indicator: "https://shared.example/removed", indicator_type: "url", lifecycle: "retracted", expires_at: expect.any(String) },
      { indicator: "https://shared.example/retained", indicator_type: "url", lifecycle: "active", expires_at: expect.any(String) },
      { indicator: "shared.example", indicator_type: "hostname", lifecycle: "active", expires_at: expect.any(String) }
    ]));
    expect(new Date(rows.find(row => row.indicator === "https://new.example/")!.expires_at).toISOString()).toBe(secondExpiry);
    expect(new Date(rows.find(row => row.indicator === "https://shared.example/retained")!.expires_at).toISOString()).toBe(secondExpiry);
    expect(new Date(rows.find(row => row.indicator === "shared.example")!.expires_at).toISOString()).toBe(firstExpiry);
    const store = createThreatIntelStore(databaseUrl);
    const lookupUrl = store.lookupUrl?.bind(store);
    if (!lookupUrl) throw new Error("URL threat lookup unavailable");
    const lookup = await lookupUrl("https://shared.example/retained", "shared.example");
    expect(lookup.findings.map(finding => finding.indicator)).toEqual(["https://shared.example/retained", "shared.example"]);
    await db`INSERT INTO threat_indicators (indicator_type, indicator, threat_type, severity, source, lifecycle, expires_at) VALUES ('url', 'https://expired.example/', 'phishing', 'critical', 'phishing_database', 'active', now() - interval '1 minute')`;
    const expiredLookup = await lookupUrl("https://expired.example/", "expired.example");
    expect(expiredLookup.findings).toEqual([]);
    await db`DELETE FROM threat_indicators WHERE source = 'phishing_database'`;
  });

  postgresTest("rolls back both scope changes on a transaction fault", async () => {
    if (!databaseUrl || !db) throw new Error("THREAT_TEST_DATABASE_URL missing");
    await db.begin(async tx => { await reconcilePhishingDatabaseSnapshot(tx, [row("url", "https://stable.example/", urlSource)], "url", "2026-09-03T00:00:00.000Z"); });
    await expect(db.begin(async tx => {
      await reconcilePhishingDatabaseSnapshot(tx, [row("url", "https://replaced.example/", urlSource)], "url", "2026-09-04T00:00:00.000Z");
      await reconcilePhishingDatabaseSnapshot(tx, [row("hostname", "replaced.example", hostnameSource)], "hostname", "2026-09-04T00:00:00.000Z");
      throw new Error("injected reconciliation fault");
    })).rejects.toThrow("injected reconciliation fault");
    expect(await db<{ indicator: string; lifecycle: string }[]>`SELECT indicator, lifecycle FROM threat_indicators WHERE source = 'phishing_database' ORDER BY indicator`).toEqual([{ indicator: "https://stable.example/", lifecycle: "active" }]);
  });

  postgresTest("validates both official feeds before mutating either scope", async () => {
    if (!databaseUrl || !db) throw new Error("THREAT_TEST_DATABASE_URL missing");
    const urlA = new TextEncoder().encode("https://atomic.example/a\n");
    const hostnameA = new TextEncoder().encode("atomic.example\n");
    await expect(syncPhishingDatabase(databaseUrl, { fetchBytes: async url => feedResponses(urlA, hostnameA).get(url)!, now: () => new Date("2026-09-05T00:00:00.000Z") })).resolves.toMatchObject({ urlImported: 1, hostnameImported: 1, expiresAt: "2026-09-05T06:00:00.000Z" });
    const urlB = new TextEncoder().encode("https://atomic.example/b\n");
    let rejected = false;
    try { await syncPhishingDatabase(databaseUrl, { fetchBytes: async url => feedResponses(urlB, hostnameA, true).get(url)!, now: () => new Date("2026-09-06T00:00:00.000Z") }); } catch (error) { rejected = error instanceof Error && error.message.includes("checksum mismatch"); }
    expect(rejected).toBe(true);
    expect(await db<{ indicator: string; lifecycle: string }[]>`SELECT indicator, lifecycle FROM threat_indicators WHERE source = 'phishing_database' ORDER BY indicator`).toEqual([
      { indicator: "atomic.example", lifecycle: "active" },
      { indicator: "https://atomic.example/a", lifecycle: "active" }
    ]);
  });
});
