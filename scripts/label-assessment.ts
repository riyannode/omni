import { createAssessmentJournal, type AssessmentLabel } from "../src/data/assessment-journal.ts";

const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i += 2) {
  const key = process.argv[i]; const value = process.argv[i + 1];
  if (!key?.startsWith("--") || value === undefined) throw new Error("usage: bun scripts/label-assessment.ts --id <uuid> --label <benign|incident> --source <provenance> [--reference <url>] [--notes <text>]");
  args.set(key.slice(2), value);
}
const id = args.get("id");
const label = args.get("label");
const source = args.get("source");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
if (!id || (label !== "benign" && label !== "incident") || !source?.trim()) throw new Error("id, canonical label, and independent source are required");
await createAssessmentJournal(process.env.DATABASE_URL).labelAssessment(id, label as AssessmentLabel, source, args.get("reference"), args.get("notes"));
console.log(JSON.stringify({ assessmentId: id, label, source, updated: true }));
