import type { ThreatFinding } from "../domain/risk.ts";

export type PhishingSnapshotScope = "url" | "hostname";
export const PHISHING_DATABASE_URL_SOURCE = "https://phish.co.za/latest/phishing-links-ACTIVE.txt" as const;
export const PHISHING_DATABASE_HOSTNAME_SOURCE = "https://phish.co.za/latest/phishing-domains-ACTIVE.txt" as const;

export type PhishingDatabaseIndicator = ThreatFinding & { source: "phishing_database"; severity: "critical"; threatType: "phishing"; reference: string };

function sourceReferenceAllowed(reference: string, scope: PhishingSnapshotScope): boolean {
  return scope === "url"
    ? reference === PHISHING_DATABASE_URL_SOURCE
    : reference === PHISHING_DATABASE_HOSTNAME_SOURCE;
}

function hostnameIndicator(value: string): string {
  const parsed = new URL(`https://${value}`);
  if (parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.port) throw new Error("invalid phishing database hostname");
  return parsed.hostname.toLowerCase();
}

export function parsePhishingDatabaseSnapshot(content: string, sourceReference: string, scope: PhishingSnapshotScope): PhishingDatabaseIndicator[] {
  if (!sourceReferenceAllowed(sourceReference, scope)) throw new Error("phishing database source reference is not official for scope");
  const indicators = new Map<string, PhishingDatabaseIndicator>();
  for (const rawLine of content.split(/\r?\n/)) {
    const value = rawLine.trim();
    if (!value || value.startsWith("#")) continue;
    let indicator: string;
    if (/^https?:\/\//i.test(value)) {
      if (scope !== "url") throw new Error("phishing database row does not match scope");
      const parsed = new URL(value);
      if (parsed.username || parsed.password) throw new Error("phishing database URL credentials rejected");
      parsed.hash = "";
      indicator = parsed.toString();
    } else {
      if (scope !== "hostname") throw new Error("phishing database row does not match scope");
      indicator = hostnameIndicator(value);
    }
    const indicatorType = scope;
    const finding: PhishingDatabaseIndicator = { indicatorType, indicator, threatType: "phishing", severity: "critical", source: "phishing_database", reference: sourceReference };
    indicators.set(`${indicatorType}:${indicator}`, finding);
  }
  const result = [...indicators.values()].sort((left, right) => left.indicator.localeCompare(right.indicator));
  if (result.length === 0) throw new Error("phishing_database_snapshot_empty");
  return result;
}
