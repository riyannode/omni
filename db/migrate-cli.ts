import { migrate } from "./migrate.ts";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL is required for db:migrate");
console.log(JSON.stringify({ task: "db_migrate", ...(await migrate(databaseUrl)) }));
