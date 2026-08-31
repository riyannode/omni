import { SQL } from "bun";
import { createHash } from "node:crypto";
import { parsePhishingDatabaseSnapshot, PHISHING_DATABASE_HOSTNAME_SOURCE, PHISHING_DATABASE_URL_SOURCE, type PhishingDatabaseIndicator, type PhishingSnapshotScope } from "./phishing-database.ts";

const MAX_FEED_BYTES = 64 * 1024 * 1024;
export const DEFAULT_PHISHING_DATABASE_MAX_AGE_HOURS = 6;
export const PHISHING_DATABASE_CHECKSUM_SOURCES = {
  url: "https://raw.githubusercontent.com/Phishing-Database/checksums/master/phishing-links-ACTIVE.txt.sha256",
  hostname: "https://raw.githubusercontent.com/Phishing-Database/checksums/master/phishing-domains-ACTIVE.txt.sha256"
} as const;

export type PhishingSyncResult = { urlImported: number; hostnameImported: number; expiresAt: string };
type FetchBytes = (url: string) => Promise<Uint8Array>;
export type PhishingSyncOptions = { fetchBytes?: FetchBytes; maxAgeHours?: number; now?: () => Date };

export function validatePhishingMaxAgeHours(value: number): number {
  if (!Number.isFinite(value) || !Number.isSafeInteger(value) || value < 1 || value > 24 * 30) throw new Error("PHISHING_DATABASE_MAX_AGE_HOURS must be an integer between 1 and 720");
  return value;
}
function sha256(bytes: Uint8Array): string { return createHash("sha256").update(bytes).digest("hex"); }
function text(bytes: Uint8Array): string { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
function approvedChecksumSource(url: string, scope: PhishingSnapshotScope): boolean {
  return url === PHISHING_DATABASE_CHECKSUM_SOURCES[scope];
}
export function parseSha256Checksum(content: Uint8Array, expectedFilename: string, sourceReference: string, scope: PhishingSnapshotScope): string {
  if (!approvedChecksumSource(sourceReference, scope)) throw new Error("phishing database checksum source is not official");
  const value = text(content).trim();
  const match = /^([0-9a-fA-F]{64})\s+\*?([^\s]+)$/.exec(value);
  if (!match || match[2] !== expectedFilename) throw new Error("phishing database checksum format invalid");
  return match[1]!.toLowerCase();
}
export function verifySha256(content: Uint8Array, checksumContent: Uint8Array, expectedFilename: string, checksumSource: string, scope: PhishingSnapshotScope): void {
  const expected = parseSha256Checksum(checksumContent, expectedFilename, checksumSource, scope);
  if (sha256(content) !== expected) throw new Error(`phishing database ${scope} checksum mismatch`);
}

async function defaultFetchBytes(url: string): Promise<Uint8Array> {
  const response = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`phishing database upstream HTTP ${response.status}`);
  const length = response.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_FEED_BYTES)) throw new Error("phishing database feed oversized");
  if (!response.body) throw new Error("phishing database response missing body");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    bytes += chunk.value.byteLength;
    if (bytes > MAX_FEED_BYTES) { await reader.cancel(); throw new Error("phishing database feed oversized"); }
    chunks.push(chunk.value);
  }
  const result = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}

export async function reconcilePhishingDatabaseSnapshot(tx: SQL, rows: PhishingDatabaseIndicator[], scope: PhishingSnapshotScope, expiresAt: string): Promise<void> {
  if (rows.length === 0 || rows.some(row => row.indicatorType !== scope || row.source !== "phishing_database")) throw new Error("phishing database snapshot scope invalid");
  await tx`CREATE TEMP TABLE phishing_snapshot (indicator text NOT NULL, threat_type text NOT NULL, severity text NOT NULL, source_reference text NOT NULL, PRIMARY KEY (indicator, threat_type)) ON COMMIT DROP`;
  await tx`
    INSERT INTO phishing_snapshot (indicator, threat_type, severity, source_reference)
    SELECT incoming.indicator, incoming.threat_type, incoming.severity, incoming.source_reference
    FROM UNNEST(
      ${tx.array(rows.map(row => row.indicator), "TEXT")},
      ${tx.array(rows.map(row => row.threatType), "TEXT")},
      ${tx.array(rows.map(row => row.severity), "TEXT")},
      ${tx.array(rows.map(row => row.reference), "TEXT")}
    ) AS incoming(indicator, threat_type, severity, source_reference)
    ON CONFLICT (indicator, threat_type) DO NOTHING
  `;
  await tx`
    UPDATE threat_indicators
    SET lifecycle = 'retracted', expires_at = now(), last_seen_at = now()
    WHERE source = 'phishing_database' AND indicator_type = ${scope} AND lifecycle = 'active'
      AND NOT EXISTS (SELECT 1 FROM phishing_snapshot incoming WHERE incoming.indicator = threat_indicators.indicator AND incoming.threat_type = threat_indicators.threat_type)
  `;
  await tx`
    INSERT INTO threat_indicators (indicator_type, indicator, threat_type, severity, source, source_reference, lifecycle, expires_at)
    SELECT ${scope}, indicator, threat_type, severity, 'phishing_database', source_reference, 'active', ${expiresAt}::timestamptz
    FROM phishing_snapshot
    ON CONFLICT (indicator_type, indicator, threat_type, source) DO UPDATE SET
      severity = EXCLUDED.severity,
      source_reference = EXCLUDED.source_reference,
      lifecycle = 'active',
      last_seen_at = now(),
      expires_at = EXCLUDED.expires_at
  `;
  await tx`DROP TABLE phishing_snapshot`;
}

export async function syncPhishingDatabase(databaseUrl: string, options: PhishingSyncOptions = {}): Promise<PhishingSyncResult> {
  const fetchBytes = options.fetchBytes ?? defaultFetchBytes;
  const maxAgeHours = validatePhishingMaxAgeHours(options.maxAgeHours ?? DEFAULT_PHISHING_DATABASE_MAX_AGE_HOURS);
  const now = options.now ? new Date(options.now()) : new Date();
  if (Number.isNaN(now.valueOf())) throw new Error("phishing database clock invalid");
  const [urlFeed, urlChecksum, hostnameFeed, hostnameChecksum] = await Promise.all([
    fetchBytes(PHISHING_DATABASE_URL_SOURCE),
    fetchBytes(PHISHING_DATABASE_CHECKSUM_SOURCES.url),
    fetchBytes(PHISHING_DATABASE_HOSTNAME_SOURCE),
    fetchBytes(PHISHING_DATABASE_CHECKSUM_SOURCES.hostname)
  ]);
  verifySha256(urlFeed, urlChecksum, "phishing-links-ACTIVE.txt", PHISHING_DATABASE_CHECKSUM_SOURCES.url, "url");
  verifySha256(hostnameFeed, hostnameChecksum, "phishing-domains-ACTIVE.txt", PHISHING_DATABASE_CHECKSUM_SOURCES.hostname, "hostname");
  const urlRows = parsePhishingDatabaseSnapshot(text(urlFeed), PHISHING_DATABASE_URL_SOURCE, "url");
  const hostnameRows = parsePhishingDatabaseSnapshot(text(hostnameFeed), PHISHING_DATABASE_HOSTNAME_SOURCE, "hostname");
  const expiresAt = new Date(now.valueOf() + maxAgeHours * 60 * 60 * 1000).toISOString();
  const db = new SQL(databaseUrl, { max: 2, idleTimeout: 30, connectionTimeout: 5 });
  const connection = await db.reserve();
  try {
    await connection`BEGIN`;
    try {
      await connection`SELECT pg_advisory_xact_lock(hashtextextended('omni:phishing-database-sync', 0))`;
      await reconcilePhishingDatabaseSnapshot(connection, urlRows, "url", expiresAt);
      await reconcilePhishingDatabaseSnapshot(connection, hostnameRows, "hostname", expiresAt);
      await connection`COMMIT`;
    } catch (error) {
      try { await connection`ROLLBACK`; } catch {}
      throw error;
    }
  } finally {
    connection.release();
    await db.close();
  }
  return { urlImported: urlRows.length, hostnameImported: hostnameRows.length, expiresAt };
}
