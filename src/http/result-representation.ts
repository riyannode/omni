import type { Response } from "express";
import type { RiskAssessment, RiskSignal, RiskLevel, RepositoryRiskSummary } from "../domain/risk.ts";
import { renderRiskMarkdown } from "./risk-markdown.ts";

export type ResultRepresentation = "json" | "markdown";

export const MAX_PUBLIC_SIGNALS = 32;
export const MAX_PUBLIC_SOURCE_ERRORS = 16;
export const MAX_PUBLIC_PACKAGES = 16;
export const MAX_PUBLIC_JSON_BYTES = 32 * 1024;
export const MAX_PUBLIC_MARKDOWN_BYTES = 16 * 1024;

const SEVERITY_RANK: Record<Exclude<RiskLevel, "unknown">, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const DETAIL_KEYS = new Set([
  "changeCount", "count", "ecosystem", "id", "indicatorType", "name", "observedCount", "observedCountsBySeverity", "reference", "retainedDetailCount", "severity", "status", "summaryStatus", "threatType", "version"
]);
const COVERAGE_STATUSES = new Set(["OBSERVED", "ABSENT", "UNAVAILABLE", "UNKNOWN", "NOT_APPLICABLE"]);
const KEV_STATUSES = new Set(["NOT_QUERIED", "CHECKED", "UNAVAILABLE", "UNKNOWN"]);
const THREAT_STATUSES = new Set(["NOT_CHECKED", "CHECKED", "UNAVAILABLE", "UNKNOWN"]);

export type CompactSignal = {
  code: string;
  severity: Exclude<RiskLevel, "unknown">;
  source: string;
  detail?: Record<string, string | number | boolean | Record<string, number>>;
};

export type PublicOmissions = {
  evidenceDetailsOmitted: number;
  dependencyDetailsOmitted: number;
  signalsOmitted?: number;
  sourceErrorsOmitted?: number;
  packagesOmitted?: number;
  coverageSourcesOmitted?: number;
  paymentOptionsOmitted?: number;
};

export type CompactRiskAssessment = Omit<RiskAssessment, "evidence" | "maliciousPackageObservations" | "signals" | "sourceErrors"> & {
  signals: CompactSignal[];
  sourceErrors: string[];
  omissions: PublicOmissions;
  maliciousPackageObservations?: { observed: number; ids: string[]; idsOmitted?: number };
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function integer(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : fallback;
}

function text(value: unknown, maximum = 256): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.replaceAll(/[\r\n]+/g, " ");
  return normalized.length <= maximum ? normalized : `${normalized.slice(0, maximum - 1)}…`;
}

function compactGatewayExtra(value: unknown): Record<string, string> | undefined {
  if (!isRecord(value)) return undefined;
  const extra: Record<string, string> = {};
  for (const key of ["name", "version", "verifyingContract"]) {
    const item = text(value[key]);
    if (item !== undefined) extra[key] = item;
  }
  return Object.keys(extra).length > 0 ? extra : undefined;
}

function boundedStrings(value: unknown, maximumEntries: number): { values: string[]; omitted: number } {
  const values = Array.isArray(value)
    ? [...new Set(value.map(item => text(item)).filter((item): item is string => item !== undefined))].sort()
    : [];
  return { values: values.slice(0, maximumEntries), omitted: Math.max(0, values.length - maximumEntries) };
}

function compactDetail(value: unknown): CompactSignal["detail"] {
  if (!isRecord(value)) return undefined;
  const detail: NonNullable<CompactSignal["detail"]> = {};
  for (const key of [...DETAIL_KEYS].sort()) {
    const item = value[key];
    if (typeof item === "string") {
      const bounded = text(item);
      if (bounded !== undefined) detail[key] = bounded;
    } else if (typeof item === "number" && Number.isFinite(item)) detail[key] = item;
    else if (typeof item === "boolean") detail[key] = item;
    else if (key === "observedCountsBySeverity" && isRecord(item)) {
      const counts: Record<string, number> = {};
      for (const level of ["unknown", "low", "medium", "high", "critical"]) counts[level] = integer(item[level]);
      detail[key] = counts;
    }
  }
  return Object.keys(detail).length > 0 ? detail : undefined;
}

function compactSignals(value: unknown): { signals: CompactSignal[]; omitted: number } {
  const source = Array.isArray(value) ? value.filter(isRecord) : [];
  const compact = source.flatMap((item, index) => {
    const code = text(item.code);
    const severity = item.severity;
    const sourceName = text(item.source);
    if (!code || !sourceName || !Object.hasOwn(SEVERITY_RANK, severity as string)) return [];
    const signal: CompactSignal = { code, severity: severity as CompactSignal["severity"], source: sourceName };
    const detail = compactDetail(item.detail);
    if (detail !== undefined) signal.detail = detail;
    return [{ signal, index }];
  });
  compact.sort((left, right) => {
    const severityDifference = SEVERITY_RANK[right.signal.severity] - SEVERITY_RANK[left.signal.severity];
    if (severityDifference !== 0) return severityDifference;
    const leftKey = `${left.signal.code}\u0000${left.signal.source}\u0000${JSON.stringify(left.signal.detail ?? {})}`;
    const rightKey = `${right.signal.code}\u0000${right.signal.source}\u0000${JSON.stringify(right.signal.detail ?? {})}`;
    return leftKey.localeCompare(rightKey) || left.index - right.index;
  });
  const invalid = Array.isArray(value) ? value.length - compact.length : 0;
  return { signals: compact.slice(0, MAX_PUBLIC_SIGNALS).map(item => item.signal), omitted: invalid + Math.max(0, compact.length - MAX_PUBLIC_SIGNALS) };
}

function compactCoverage(value: unknown): { coverage: CompactRiskAssessment["coverage"]; omitted: number } {
  if (!isRecord(value)) return { coverage: undefined, omitted: 0 };
  const rawSources = Array.isArray(value.sources) ? value.sources : [];
  const sourceValues = rawSources.filter(isRecord).slice(0, 16).flatMap(source => {
    const name = text(source.source);
    const execution = source.execution === "QUERIED" || source.execution === "NOT_QUERIED" ? source.execution as "QUERIED" | "NOT_QUERIED" : undefined;
    const status = typeof source.status === "string" && COVERAGE_STATUSES.has(source.status) ? source.status as NonNullable<CompactRiskAssessment["coverage"]>["sources"][number]["status"] : undefined;
    const weight = typeof source.weight === "number" && Number.isFinite(source.weight) && source.weight >= 0 ? source.weight : undefined;
    return name && execution && status && weight !== undefined ? [{ source: name, execution, status, weight }] : [];
  });
  const modelVersion = text(value.modelVersion);
  const resolvedWeight = typeof value.resolvedWeight === "number" ? value.resolvedWeight : undefined;
  const applicableWeight = typeof value.applicableWeight === "number" ? value.applicableWeight : undefined;
  if (!modelVersion || resolvedWeight === undefined || applicableWeight === undefined) return { coverage: undefined, omitted: rawSources.length };
  return { coverage: { modelVersion, resolvedWeight, applicableWeight, sources: sourceValues }, omitted: Math.max(0, rawSources.length - sourceValues.length) };
}

function compactRepositorySummary(value: unknown): RepositoryRiskSummary | undefined {
  if (!isRecord(value) || !isRecord(value.dependencies) || !isRecord(value.vulnerabilities) || !isRecord(value.knownExploitation) || !isRecord(value.maliciousPackages) || !isRecord(value.threatIntelligence) || !isRecord(value.provenance) || !isRecord(value.securityPractices)) return undefined;
  const vulnerabilities = value.vulnerabilities;
  const highestSeverity = vulnerabilities.highestSeverity === null || vulnerabilities.highestSeverity === "unknown" || Object.hasOwn(SEVERITY_RANK, vulnerabilities.highestSeverity as string) ? vulnerabilities.highestSeverity as RepositoryRiskSummary["vulnerabilities"]["highestSeverity"] : null;
  const threat = value.threatIntelligence;
  const threatHighest = threat.highestSeverity === null || Object.hasOwn(SEVERITY_RANK, threat.highestSeverity as string) ? threat.highestSeverity as RepositoryRiskSummary["threatIntelligence"]["highestSeverity"] : null;
  const kevStatus = typeof value.knownExploitation.status === "string" && KEV_STATUSES.has(value.knownExploitation.status) ? value.knownExploitation.status as RepositoryRiskSummary["knownExploitation"]["status"] : "UNKNOWN";
  const threatStatus = typeof threat.status === "string" && THREAT_STATUSES.has(threat.status) ? threat.status as RepositoryRiskSummary["threatIntelligence"]["status"] : "UNKNOWN";
  return {
    dependencies: { exact: integer(value.dependencies.exact), unresolved: integer(value.dependencies.unresolved), resolutionComplete: value.dependencies.resolutionComplete === true },
    vulnerabilities: { total: integer(vulnerabilities.total), unknown: integer(vulnerabilities.unknown), low: integer(vulnerabilities.low), medium: integer(vulnerabilities.medium), high: integer(vulnerabilities.high), critical: integer(vulnerabilities.critical), highestSeverity },
    knownExploitation: { kevMatches: integer(value.knownExploitation.kevMatches), status: kevStatus },
    maliciousPackages: { observed: integer(value.maliciousPackages.observed) },
    threatIntelligence: { status: threatStatus, findings: integer(threat.findings), highestSeverity: threatHighest },
    provenance: { sourceMismatch: integer(value.provenance.sourceMismatch), commitMismatch: integer(value.provenance.commitMismatch), unavailable: integer(value.provenance.unavailable) },
    securityPractices: { mutableActions: integer(value.securityPractices.mutableActions), workflowWritePermissions: integer(value.securityPractices.workflowWritePermissions), downloadExecuteFindings: integer(value.securityPractices.downloadExecuteFindings) }
  };
}

function compactRiskAssessment(value: Record<string, unknown>): CompactRiskAssessment {
  const signalResult = compactSignals(value.signals);
  const errors = boundedStrings(value.sourceErrors, MAX_PUBLIC_SOURCE_ERRORS);
  const existingOmissions = isRecord(value.omissions) ? value.omissions : {};
  const evidenceCount = Array.isArray(value.evidence) ? value.evidence.length : integer(existingOmissions.evidenceDetailsOmitted);
  const summary = compactRepositorySummary(value.repositorySummary);
  const existingDependencyOmissions = integer(existingOmissions.dependencyDetailsOmitted);
  const dependencyDetailsOmitted = summary ? summary.dependencies.exact + summary.dependencies.unresolved : existingDependencyOmissions;
  const result: CompactRiskAssessment = {
    subject: value.subject as CompactRiskAssessment["subject"],
    policyVersion: text(value.policyVersion) ?? "unknown",
    scoreStatus: value.scoreStatus as CompactRiskAssessment["scoreStatus"],
    recommendation: value.recommendation as CompactRiskAssessment["recommendation"],
    riskScore: integer(value.riskScore),
    evidenceCoverage: typeof value.evidenceCoverage === "number" ? value.evidenceCoverage : 0,
    dimensions: value.dimensions as CompactRiskAssessment["dimensions"],
    signals: signalResult.signals,
    sourceErrors: errors.values,
    omissions: {
      evidenceDetailsOmitted: evidenceCount,
      dependencyDetailsOmitted,
      ...(signalResult.omitted > 0 || integer(existingOmissions.signalsOmitted) > 0 ? { signalsOmitted: signalResult.omitted || integer(existingOmissions.signalsOmitted) } : {}),
      ...(errors.omitted > 0 || integer(existingOmissions.sourceErrorsOmitted) > 0 ? { sourceErrorsOmitted: errors.omitted || integer(existingOmissions.sourceErrorsOmitted) } : {})
    },
    assessedAt: text(value.assessedAt) ?? "unknown",
    freshness: value.freshness as CompactRiskAssessment["freshness"]
  };
  const coverage = compactCoverage(value.coverage);
  if (coverage.coverage !== undefined) result.coverage = coverage.coverage;
  const coverageSourcesOmitted = Math.max(coverage.omitted, integer(existingOmissions.coverageSourcesOmitted));
  if (coverageSourcesOmitted > 0) result.omissions.coverageSourcesOmitted = coverageSourcesOmitted;
  if (summary !== undefined) result.repositorySummary = summary;
  const rawMaliciousObservations = Array.isArray(value.maliciousPackageObservations) ? value.maliciousPackageObservations : [];
  const compactMaliciousObservations = isRecord(value.maliciousPackageObservations) ? value.maliciousPackageObservations : undefined;
  const maliciousObservations = rawMaliciousObservations.length > 0
    ? rawMaliciousObservations.length
    : integer(compactMaliciousObservations?.observed);
  const maliciousIds = rawMaliciousObservations.length > 0
    ? [...new Set(rawMaliciousObservations.flatMap(item => isRecord(item) ? [text(item.id)].filter((id): id is string => id !== undefined) : []))].sort()
    : (Array.isArray(compactMaliciousObservations?.ids) ? compactMaliciousObservations.ids.map(item => text(item)).filter((item): item is string => item !== undefined).slice(0, 16) : []);
  const maliciousIdsOmitted = rawMaliciousObservations.length > 0
    ? Math.max(0, maliciousIds.length - 16)
    : integer(compactMaliciousObservations?.idsOmitted);
  if (maliciousObservations > 0) result.maliciousPackageObservations = { observed: maliciousObservations, ids: maliciousIds.slice(0, 16), ...(maliciousIdsOmitted > 0 ? { idsOmitted: maliciousIdsOmitted } : {}) };
  const preflight = isRecord(value.preflightContext) ? value.preflightContext : undefined;
  if (preflight) {
    const resource = text(preflight.resource, 2048);
    const rawPaymentOptions = Array.isArray(preflight.paymentOptions) ? preflight.paymentOptions : [];
    const paymentOptions = rawPaymentOptions.filter(isRecord).slice(0, 8).flatMap(option => {
      const compactOption: Record<string, unknown> = {};
      for (const key of ["scheme", "network", "amount", "asset", "payTo"]) {
        const item = text(option[key]);
        if (item !== undefined) compactOption[key] = item;
      }
      if (typeof option.maxTimeoutSeconds === "number" && Number.isSafeInteger(option.maxTimeoutSeconds)) compactOption.maxTimeoutSeconds = option.maxTimeoutSeconds;
      const extra = compactGatewayExtra(option.extra);
      if (extra !== undefined) compactOption.extra = extra;
      return Object.keys(compactOption).length > 0 ? [compactOption] : [];
    });
    const paymentOptionsOmitted = Math.max(rawPaymentOptions.length - paymentOptions.length, integer(existingOmissions.paymentOptionsOmitted));
    if (paymentOptionsOmitted > 0) result.omissions.paymentOptionsOmitted = paymentOptionsOmitted;
    if (resource !== undefined) (result as Record<string, unknown>).preflightContext = { resource, paymentOptions };
  }
  return result;
}

function compactDependencyAssessment(value: Record<string, unknown>): Record<string, unknown> {
  const packages = Array.isArray(value.packages) ? value.packages.filter(isRecord) : [];
  const compactPackages = packages.map((item, index) => ({ item: compactRiskAssessment(item), index }));
  compactPackages.sort((left, right) => {
    const scoreDifference = integer(right.item.riskScore) - integer(left.item.riskScore);
    return scoreDifference || String((left.item.subject as { id?: string })?.id ?? "").localeCompare(String((right.item.subject as { id?: string })?.id ?? "")) || left.index - right.index;
  });
  const summary = isRecord(value.summary) ? {
    count: integer(value.summary.count),
    worstRiskScore: integer(value.summary.worstRiskScore),
    recommendations: isRecord(value.summary.recommendations) ? Object.fromEntries(Object.entries(value.summary.recommendations).filter(([, count]) => Number.isSafeInteger(count) && (count as number) >= 0).sort(([left], [right]) => left.localeCompare(right))) : {}
  } : { count: packages.length, worstRiskScore: 0, recommendations: {} };
  const existingOmissions = isRecord(value.omissions) ? value.omissions : {};
  const existingPackagesOmitted = integer(existingOmissions.packagesOmitted);
  const packagesOmitted = Math.max(existingPackagesOmitted, packages.length > MAX_PUBLIC_PACKAGES ? packages.length - MAX_PUBLIC_PACKAGES : 0);
  return {
    packages: compactPackages.slice(0, MAX_PUBLIC_PACKAGES).map(item => item.item),
    summary,
    assessedAt: text(value.assessedAt) ?? "unknown",
    omissions: {
      evidenceDetailsOmitted: integer(existingOmissions.evidenceDetailsOmitted) + compactPackages.reduce((total, entry) => total + integer((entry.item.omissions as Record<string, unknown> | undefined)?.evidenceDetailsOmitted), 0),
      dependencyDetailsOmitted: Math.max(packages.length, integer(existingOmissions.dependencyDetailsOmitted)),
      ...(packagesOmitted > 0 ? { packagesOmitted } : {})
    }
  };
}

export function compactResultForHttp(result: unknown): unknown {
  if (!isRecord(result)) return result;
  if (Array.isArray(result.packages) && isRecord(result.summary)) return compactDependencyAssessment(result);
  if (isRecord(result.subject)) return compactRiskAssessment(result);
  return result;
}

export function representationFromAccept(accepted: string | false): ResultRepresentation | undefined {
  if (accepted === false) return undefined;
  return accepted === "markdown" ? "markdown" : "json";
}

export function sendResult(res: Response, status: number, result: unknown, representation: ResultRepresentation, _route: string): void {
  res.vary("Accept");
  if (representation === "markdown") {
    const markdown = renderRiskMarkdown(result);
    if (Buffer.byteLength(markdown, "utf8") > MAX_PUBLIC_MARKDOWN_BYTES) {
      res.status(500).json({ error: "response_representation_too_large", retryable: false });
      return;
    }
    res.status(status).type("text/markdown").send(markdown);
    return;
  }
  const response = status >= 200 && status < 300 ? compactResultForHttp(result) : result;
  if (status >= 200 && status < 300 && Buffer.byteLength(JSON.stringify(response), "utf8") > MAX_PUBLIC_JSON_BYTES) {
    res.status(500).json({ error: "response_representation_too_large", retryable: false });
    return;
  }
  res.status(status).json(response);
}
