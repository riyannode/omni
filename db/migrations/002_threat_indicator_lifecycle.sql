ALTER TABLE threat_indicators
  ADD COLUMN lifecycle text NOT NULL DEFAULT 'active';

ALTER TABLE threat_indicators
  DROP CONSTRAINT IF EXISTS threat_indicators_lifecycle_check;

ALTER TABLE threat_indicators
  ADD CONSTRAINT threat_indicators_lifecycle_check
  CHECK (lifecycle IN ('active', 'retracted'));
