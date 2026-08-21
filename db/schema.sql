CREATE TABLE IF NOT EXISTS endpoint_state (
  resource text PRIMARY KEY,
  fingerprint text NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS endpoint_observations (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  resource text NOT NULL,
  fingerprint text NOT NULL,
  provider_name text,
  pay_to text,
  method text,
  price_atomic text,
  network text,
  schema_hash text,
  supports_gateway boolean,
  supports_vanilla boolean,
  observed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS endpoint_observations_resource_time ON endpoint_observations (resource, observed_at DESC);
CREATE INDEX IF NOT EXISTS endpoint_observations_pay_to_time ON endpoint_observations (pay_to, observed_at DESC);

-- Vendor-neutral IOC store. Only import data you are licensed to use in a commercial API.
CREATE TABLE IF NOT EXISTS threat_indicators (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  indicator_type text NOT NULL CHECK (indicator_type IN ('url', 'hostname', 'wallet', 'package')),
  indicator text NOT NULL,
  threat_type text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  source text NOT NULL,
  source_reference text,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  UNIQUE (indicator_type, indicator, threat_type, source)
);
CREATE INDEX IF NOT EXISTS threat_indicators_lookup ON threat_indicators (indicator_type, indicator);
CREATE INDEX IF NOT EXISTS threat_indicators_expiry ON threat_indicators (expires_at);

CREATE TABLE IF NOT EXISTS assessment_records (
  assessment_id uuid PRIMARY KEY,
  subject_type text NOT NULL CHECK (subject_type IN ('package', 'repository', 'dependency_set', 'x402_endpoint')),
  subject_id text NOT NULL,
  snapshot_schema_version integer NOT NULL CHECK (snapshot_schema_version > 0),
  feature_schema_version integer NOT NULL CHECK (feature_schema_version > 0),
  policy_version text NOT NULL,
  snapshot jsonb NOT NULL,
  features jsonb NOT NULL,
  assessment jsonb NOT NULL,
  assessed_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS assessment_records_subject_time ON assessment_records (subject_type, subject_id, assessed_at DESC);
CREATE INDEX IF NOT EXISTS assessment_records_policy ON assessment_records (policy_version);
CREATE INDEX IF NOT EXISTS assessment_records_assessed_at ON assessment_records (assessed_at DESC);

CREATE TABLE IF NOT EXISTS assessment_labels (
  assessment_id uuid PRIMARY KEY REFERENCES assessment_records(assessment_id) ON DELETE CASCADE,
  label text NOT NULL CHECK (label IN ('benign', 'incident')),
  source text NOT NULL CHECK (length(trim(source)) > 0),
  source_reference text,
  notes text,
  labeled_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
