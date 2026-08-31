import type { ThreatFinding } from "../domain/risk.ts";

export type PhishingDatabaseIndicator = ThreatFinding & { source: "phishing_database"; severity: "critical"; threatType: "phishing"; reference: string };

function sourceReferenceAllowed(reference: string): boolean {
  try {
    const url = new URL(reference);
    return url.protocol === "https:" && ((url.hostname === "github.com" && url.pathname.startsWith("/Phishing-Database/Phishing.Database/")) || (url.hostname === "raw.githubusercontent.com" && url.pathname.startsWith("/Phishing-Database/Phishing.Database/")) || (url.hostname === "phish.co.za" && url.pathname.startsWith("/latest/")));
  } catch { return false; }
}

function hostnameIndicator(value: string): string {
  const parsed = new URL(`https://${value}`);
  if (parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) throw new Error("invalid phishing database hostname");
  return parsed.hostname.toLowerCase();
}

export function parsePhishingDatabaseSnapshot(content: string, sourceReference: string): PhishingDatabaseIndicator[] {
  if (!sourceReferenceAllowed(sourceReference)) throw new Error("phishing database source reference is not official");
  const indicators = new Map<string, PhishingDatabaseIndicator>();
  for (const rawLine of content.split(/\r?\n/)) {
    const value = rawLine.trim();
    if (!value || value.startsWith("#")) continue;
    let indicatorType: "url" | "hostname";
    let indicator: string;
    if (/^https?:\/\//i.test(value)) {
      const parsed = new URL(value);
      if (parsed.username || parsed.password) throw new Error("phishing database URL credentials rejected");
      parsed.hash = "";
      indicatorType = "url";
      indicator = parsed.toString();
    } else {
      indicatorType = "hostname";
      indicator = hostnameIndicator(value);
    }
    const finding: PhishingDatabaseIndicator = { indicatorType, indicator, threatType: "phishing", severity: "critical", source: "phishing_database", reference: sourceReference };
    indicators.set(`${indicatorType}:${indicator}`, finding);
    if (indicatorType === "url") indicators.set(`hostname:${new URL(indicator).hostname.toLowerCase()}`, { ...finding, indicatorType: "hostname", indicator: new URL(indicator).hostname.toLowerCase() });
  }
  const result = [...indicators.values()].sort((left, right) => left.indicatorType.localeCompare(right.indicatorType) || left.indicator.localeCompare(right.indicator));
  if (result.length === 0) throw new Error("phishing_database_snapshot_empty");
  return result;
}
