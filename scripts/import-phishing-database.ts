import { readFile } from "node:fs/promises";
import { SQL } from "bun";
import { parsePhishingDatabaseSnapshot } from "../src/providers/phishing-database.ts";

const path = process.argv[2];
const sourceReference = process.argv[3];
const databaseUrl = process.env.DATABASE_URL;
if (!path || !sourceReference || !databaseUrl) throw new Error("usage: DATABASE_URL=... bun scripts/import-phishing-database.ts snapshot.txt https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE-NOW.txt");
const rows = parsePhishingDatabaseSnapshot(await readFile(path, "utf8"), sourceReference);
const db = new SQL(databaseUrl, { max: 5 });
try {
  await db.begin(async tx => {
    await tx`UPDATE threat_indicators SET lifecycle = 'retracted', expires_at = now(), last_seen_at = now() WHERE source = 'phishing_database' AND lifecycle = 'active'`;
    for (const row of rows) {
      await tx`
        INSERT INTO threat_indicators (indicator_type, indicator, threat_type, severity, source, source_reference, lifecycle, expires_at)
        VALUES (${row.indicatorType}, ${row.indicator}, ${row.threatType}, ${row.severity}, ${row.source}, ${row.reference}, 'active', NULL)
        ON CONFLICT (indicator_type, indicator, threat_type, source) DO UPDATE SET
          severity = EXCLUDED.severity,
          source_reference = EXCLUDED.source_reference,
          lifecycle = 'active',
          last_seen_at = now(),
          expires_at = NULL
      `;
    }
  });
  console.log(JSON.stringify({ source: "phishing_database", imported: rows.length, retractedAbsentFromSnapshot: true }));
} finally {
  await db.close();
}
