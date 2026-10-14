-- Migration 003 by reserved sequencing: add 'agent' to the assessment_records
-- subject_type CHECK constraint. It is intentionally numbered 003 to remain
-- compatible with the pending PR #23 sequence, which is expected to own 001 and
-- 002. Current main may not contain those migrations or PR #23's migration runner.
--
-- This migration is ADDITIVE: it widens the allowed values for subject_type to
-- include 'agent'. Existing rows are unaffected. Apply it explicitly to each
-- existing database before relying on agent journal persistence. It is not
-- automatically applied by the current db/init.ts, which directly applies only
-- db/schema.sql.
--
-- Safety: This migration is idempotent when run against Postgres 12+.
-- It uses ALTER TABLE ... DROP CONSTRAINT / ADD CONSTRAINT which acquires
-- an ACCESS EXCLUSIVE lock on the table. Run during a maintenance window
-- or as part of a zero-downtime deploy where the service is briefly paused.
--
-- DO NOT run this automatically. Apply manually and verify on a staging DB first.
-- DO NOT modify the production database from the source repo or CI pipeline.

BEGIN;

-- Drop the existing constraint (name matches db/schema.sql)
ALTER TABLE assessment_records
  DROP CONSTRAINT IF EXISTS assessment_records_subject_type_check;

-- Re-add with the widened enum including 'agent'
ALTER TABLE assessment_records
  ADD CONSTRAINT assessment_records_subject_type_check
    CHECK (subject_type IN ('package', 'repository', 'dependency_set', 'x402_endpoint', 'agent'));

COMMIT;
