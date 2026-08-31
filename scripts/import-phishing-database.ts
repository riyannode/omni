import { DEFAULT_PHISHING_DATABASE_MAX_AGE_HOURS, syncPhishingDatabase, validatePhishingMaxAgeHours } from "../src/providers/phishing-database-sync.ts";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL is required for threats:phishing:sync");
const configuredAge = process.env.PHISHING_DATABASE_MAX_AGE_HOURS;
const maxAgeHours = configuredAge === undefined ? DEFAULT_PHISHING_DATABASE_MAX_AGE_HOURS : validatePhishingMaxAgeHours(Number(configuredAge));
const result = await syncPhishingDatabase(databaseUrl, { maxAgeHours });
console.log(JSON.stringify({ task: "phishing_database_sync", ...result }));
