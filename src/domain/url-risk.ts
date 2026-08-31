export const URL_RISK_SNAPSHOT_SCHEMA_VERSION = 1 as const;
export const URL_RISK_FEATURE_SCHEMA_VERSION = 1 as const;
export const URL_RISK_POLICY_VERSION = "omni-url-risk-v1" as const;
export const MAX_URL_RISK_INPUT_LENGTH = 2048;

export type UrlRiskTarget = { url: string; hostname: string };
export type UrlAddressClassification = "public" | "private" | "loopback" | "link_local" | "multicast" | "unspecified" | "reserved";
export type UrlResolvedAddress = { address: string; family: 4 | 6; classification: UrlAddressClassification };
export type UrlDnsObservation = { addresses: UrlResolvedAddress[]; cname: string[] };
export type UrlRdapObservation = { status: "registered" | "not_found" | "unavailable"; handle?: string; ldhName?: string; registrar?: string; events?: Array<{ eventAction: string; eventDate: string }> };
export type UrlTlsObservation = { status: "valid" | "invalid" | "unavailable"; authorized?: boolean; hostnameMatch?: boolean; validFrom?: string; validTo?: string; issuer?: string };
export type UrlHttpObservation = {
  status: "observed" | "blocked" | "unavailable";
  statusCode?: number;
  contentType?: string;
  finalUrl?: string;
  redirects: Array<{ from: string; to: string; statusCode: number }>;
  httpsDowngradeBlocked?: boolean;
  securityHeaders: { hsts?: boolean; contentSecurityPolicy?: boolean; xContentTypeOptions?: boolean };
};

export type UrlRiskSnapshot = {
  subject: { type: "url"; id: string };
  url: string;
  hostname: string;
  threatIntelChecked: boolean;
  threatFindings: import("./risk.ts").ThreatFinding[];
  dns?: UrlDnsObservation;
  rdap?: UrlRdapObservation;
  tls?: UrlTlsObservation;
  http?: UrlHttpObservation;
  evidence: import("./risk.ts").Evidence[];
  sourceErrors: string[];
};

export type UrlRiskDimensions = {
  threatReputation: import("./risk.ts").RiskLevel;
  domainIdentity: import("./risk.ts").RiskLevel;
  transportSecurity: import("./risk.ts").RiskLevel;
  networkBehavior: import("./risk.ts").RiskLevel;
};

export type UrlRiskAssessment = {
  subject: UrlRiskSnapshot["subject"];
  policyVersion: typeof URL_RISK_POLICY_VERSION;
  recommendation: import("./risk.ts").Recommendation;
  riskScore: number;
  evidenceCoverage: number;
  dimensions: {
    knownVulnerabilities: "unknown";
    knownExploitation: "unknown";
    packageSupplyChain: "unknown";
    repositorySecurityPractices: "unknown";
    maliciousInfrastructure: import("./risk.ts").RiskLevel;
    serviceIdentity: import("./risk.ts").RiskLevel;
    paymentConfigurationRisk: "unknown";
    endpointOperationalRisk: import("./risk.ts").RiskLevel;
  };
  urlDimensions: UrlRiskDimensions;
  signals: import("./risk.ts").RiskSignal[];
  evidence: import("./risk.ts").Evidence[];
  sourceErrors: string[];
  assessedAt: string;
  freshness: { oldestEvidenceAt: string | null; newestEvidenceAt: string | null; expiresAt?: string };
};

export type UrlRiskFeatures = {
  schemaVersion: typeof URL_RISK_FEATURE_SCHEMA_VERSION;
  subject: UrlRiskSnapshot["subject"];
  threatMatchSeverity: import("./risk.ts").RiskLevel;
  hasDisallowedAddress: boolean;
  tlsInvalid: boolean;
  httpsDowngradeBlocked: boolean;
  redirectCount: number;
  serverError: boolean;
  missingSecurityHeaderCount: number;
  sourceErrorCount: number;
  completedSources: number;
  expectedSources: number;
};

export function normalizeUrlRiskTarget(raw: string): UrlRiskTarget {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_URL_RISK_INPUT_LENGTH) throw new Error("invalid_url");
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new Error("invalid_url"); }
  if (parsed.protocol !== "https:") throw new Error("https_required");
  if (parsed.username || parsed.password) throw new Error("url_credentials_rejected");
  parsed.hash = "";
  if (!parsed.hostname) throw new Error("invalid_url");
  const hostname = parsed.hostname.toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
  return { url: parsed.toString(), hostname };
}

function severityRank(value: import("./risk.ts").RiskLevel): number {
  return { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 }[value];
}

export function extractUrlRiskFeatures(snapshot: UrlRiskSnapshot): UrlRiskFeatures {
  const threatMatchSeverity = snapshot.threatFindings.reduce<import("./risk.ts").RiskLevel>((worst, finding) => severityRank(finding.severity) > severityRank(worst) ? finding.severity : worst, "low");
  const expectedSources = 5;
  const completedSources = [snapshot.dns, snapshot.rdap, snapshot.tls, snapshot.http, snapshot.threatIntelChecked].filter(Boolean).length;
  return {
    schemaVersion: URL_RISK_FEATURE_SCHEMA_VERSION,
    subject: snapshot.subject,
    threatMatchSeverity,
    hasDisallowedAddress: snapshot.dns?.addresses.some(address => address.classification !== "public") ?? false,
    tlsInvalid: snapshot.tls?.status === "invalid",
    httpsDowngradeBlocked: snapshot.http?.httpsDowngradeBlocked === true,
    redirectCount: snapshot.http?.redirects.length ?? 0,
    serverError: (snapshot.http?.statusCode ?? 0) >= 500,
    missingSecurityHeaderCount: snapshot.http ? [snapshot.http.securityHeaders.hsts, snapshot.http.securityHeaders.contentSecurityPolicy, snapshot.http.securityHeaders.xContentTypeOptions].filter(value => value === false).length : 0,
    sourceErrorCount: snapshot.sourceErrors.length,
    completedSources,
    expectedSources
  };
}
