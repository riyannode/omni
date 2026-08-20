import { SQL } from "bun";
import { readFile } from "node:fs/promises";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required for db:init");
}

const db = new SQL(process.env.DATABASE_URL);
const schema = await readFile(new URL("./schema.sql", import.meta.url), "utf8");
await db.unsafe(schema);
await db.close();
console.log("OMNI schema initialized");
