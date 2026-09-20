-- Migration 003: add 'agent' to subject_type CHECK constraint in assessment_records.
--
-- This migration is ADDITIVE: it widens the allowed values for the subject_type
-- column to include 'agent'. Existing rows are unaffected.
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
