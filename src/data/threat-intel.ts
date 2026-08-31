import { SQL } from "bun";
import type { ThreatFinding } from "../domain/risk.ts";

export type ThreatIntelStatus = { available: boolean; configured: boolean; activeIndicators: number; sources: number };
export type ThreatLookup = { checked: boolean; findings: ThreatFinding[] };
export type UrlThreatIntelStore = { lookupUrl(resource: string, hostname: string): Promise<ThreatLookup> };

export interface ThreatIntelStore {
  lookupEndpoint(resource: string, payTo?: string): Promise<ThreatLookup>;
  lookupUrl?(resource: string, hostname: string): Promise<ThreatLookup>;
  lookupPackage(ecosystem: string, name: string, version: string): Promise<ThreatLookup>;
  status(): Promise<ThreatIntelStatus>;
}

class NoopThreatIntelStore implements ThreatIntelStore {
  async lookupEndpoint(): Promise<ThreatLookup> { return { checked: false, findings: [] }; }
  async lookupUrl(): Promise<ThreatLookup> { return { checked: false, findings: [] }; }
  async lookupPackage(): Promise<ThreatLookup> { return { checked: false, findings: [] }; }
  async status(): Promise<ThreatIntelStatus> { return { available: false, configured: false, activeIndicators: 0, sources: 0 }; }
}

type ThreatRow = {
  indicator_type: ThreatFinding["indicatorType"];
  indicator: string;
  threat_type: string;
  severity: Exclude<ThreatFinding["severity"], "unknown">;
  source: string;
  source_reference: string | null;
};

class PostgresThreatIntelStore implements ThreatIntelStore {
  private readonly db: SQL;
  constructor(url: string) { this.db = new SQL(url, { max: 20, idleTimeout: 30, connectionTimeout: 5 }); }

  private async configured(types: ThreatFinding["indicatorType"][]): Promise<boolean> {
    const rows = await this.db`SELECT 1 FROM threat_indicators WHERE indicator_type = ANY(${this.db.array(types)}) AND lifecycle = 'active' AND (expires_at IS NULL OR expires_at > now()) LIMIT 1`;
    return rows.length > 0;
  }

  private map(rows: ThreatRow[]): ThreatFinding[] {
    return rows.map(row => ({ indicatorType: row.indicator_type, indicator: row.indicator, threatType: row.threat_type, severity: row.severity, source: row.source, ...(row.source_reference ? { reference: row.source_reference } : {}) }));
  }

  async lookupEndpoint(resource: string, payTo?: string): Promise<ThreatLookup> {
    if (!await this.configured(["url", "hostname", "wallet"])) return { checked: false, findings: [] };
    const url = new URL(resource);
    const normalizedUrl = url.toString();
    const hostname = url.hostname.toLowerCase();
    const wallet = payTo?.toLowerCase() ?? "";
    const rows = await this.db<ThreatRow[]>`
      SELECT indicator_type, indicator, threat_type, severity, source, source_reference
      FROM threat_indicators
      WHERE lifecycle = 'active' AND (expires_at IS NULL OR expires_at > now()) AND (
        (indicator_type = 'url' AND indicator = ${normalizedUrl}) OR
        (indicator_type = 'hostname' AND indicator = ${hostname}) OR
        (indicator_type = 'wallet' AND indicator = ${wallet})
      )
      ORDER BY last_seen_at DESC
      LIMIT 100
    `;
    return { checked: true, findings: this.map(rows) };
  }

  async lookupUrl(resource: string, hostname: string): Promise<ThreatLookup> {
    if (!await this.configured(["url", "hostname"])) return { checked: false, findings: [] };
    const url = new URL(resource);
    url.hash = "";
    const rows = await this.db<ThreatRow[]>`
      SELECT indicator_type, indicator, threat_type, severity, source, source_reference
      FROM threat_indicators
      WHERE lifecycle = 'active' AND (expires_at IS NULL OR expires_at > now()) AND (
        (indicator_type = 'url' AND indicator = ${url.toString()}) OR
        (indicator_type = 'hostname' AND indicator = ${hostname.toLowerCase()})
      )
      ORDER BY last_seen_at DESC
      LIMIT 100
    `;
    return { checked: true, findings: this.map(rows) };
  }

  async lookupPackage(ecosystem: string, name: string, version: string): Promise<ThreatLookup> {
    if (!await this.configured(["package"])) return { checked: false, findings: [] };
    const exact = `${ecosystem}:${name}@${version}`.toLowerCase();
    const unversioned = `${ecosystem}:${name}`.toLowerCase();
    const rows = await this.db<ThreatRow[]>`
      SELECT indicator_type, indicator, threat_type, severity, source, source_reference
      FROM threat_indicators
      WHERE lifecycle = 'active' AND (expires_at IS NULL OR expires_at > now())
        AND indicator_type = 'package'
        AND indicator IN (${exact}, ${unversioned})
      ORDER BY last_seen_at DESC
      LIMIT 100
    `;
    return { checked: true, findings: this.map(rows) };
  }

  async status(): Promise<ThreatIntelStatus> {
    try {
      const rows = await this.db<{ active_indicators: number; sources: number }[]>`
        SELECT count(*)::int AS active_indicators, count(DISTINCT source)::int AS sources
        FROM threat_indicators
        WHERE lifecycle = 'active' AND (expires_at IS NULL OR expires_at > now())
      `;
      const first = rows[0];
      return { available: true, configured: (first?.active_indicators ?? 0) > 0, activeIndicators: first?.active_indicators ?? 0, sources: first?.sources ?? 0 };
    } catch {
      return { available: false, configured: false, activeIndicators: 0, sources: 0 };
    }
  }
}

export function createThreatIntelStore(databaseUrl?: string): ThreatIntelStore {
  return databaseUrl ? new PostgresThreatIntelStore(databaseUrl) : new NoopThreatIntelStore();
}
