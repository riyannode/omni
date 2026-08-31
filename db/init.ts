import { SQL } from "bun";
import { readFile } from "node:fs/promises";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required for db:init");
}

const db = new SQL(process.env.DATABASE_URL);
const schema = await readFile(new URL("./schema.sql", import.meta.url), "utf8");
await db.unsafe(schema);
await db.unsafe(`
  ALTER TABLE threat_indicators ADD COLUMN IF NOT EXISTS lifecycle text NOT NULL DEFAULT 'active';
  ALTER TABLE threat_indicators DROP CONSTRAINT IF EXISTS threat_indicators_lifecycle_check;
  ALTER TABLE threat_indicators ADD CONSTRAINT threat_indicators_lifecycle_check CHECK (lifecycle IN ('active', 'retracted'));
`);
await db.close();
console.log("OMNI schema initialized");
