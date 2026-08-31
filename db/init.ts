import { migrate } from "./migrate.ts";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required for db:init");
}

console.log(JSON.stringify({ task: "db_init", ...(await migrate(process.env.DATABASE_URL)) }));
