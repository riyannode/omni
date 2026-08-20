import { readFile } from "node:fs/promises";
import { SQL } from "bun";
import { z } from "zod";

const rowSchema = z.object({
  indicatorType: z.enum(["url", "hostname", "wallet", "package"]),
  indicator: z.string().min(1).max(4096),
  threatType: z.string().min(1).max(128),
  severity: z.enum(["low", "medium", "high", "critical"]),
  source: z.string().min(1).max(128),
  reference: z.string().max(2048).optional(),
  expiresAt: z.string().datetime().optional()
});

const path = process.argv[2];
const databaseUrl = process.env.DATABASE_URL;
if (!path || !databaseUrl) throw new Error("usage: DATABASE_URL=... bun scripts/import-threat-intel.ts indicators.ndjson");
const db = new SQL(databaseUrl, { max: 5 });
const lines = (await readFile(path, "utf8")).split(/\r?\n/).filter(Boolean);
let imported = 0;
for (const line of lines) {
  const row = rowSchema.parse(JSON.parse(line));
  const indicator = row.indicatorType === "hostname" || row.indicatorType === "wallet" || row.indicatorType === "package"
    ? row.indicator.toLowerCase() : new URL(row.indicator).toString();
  await db`
    INSERT INTO threat_indicators (indicator_type, indicator, threat_type, severity, source, source_reference, expires_at)
    VALUES (${row.indicatorType}, ${indicator}, ${row.threatType}, ${row.severity}, ${row.source}, ${row.reference ?? null}, ${row.expiresAt ?? null})
    ON CONFLICT (indicator_type, indicator, threat_type, source) DO UPDATE SET
      severity = EXCLUDED.severity,
      source_reference = EXCLUDED.source_reference,
      last_seen_at = now(),
      expires_at = EXCLUDED.expires_at
  `;
  imported += 1;
}
console.log(JSON.stringify({ imported }));
await db.close();
