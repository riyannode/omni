import { compactResultForHttp, type CompactRiskAssessment, type CompactSignal } from "./result-representation.ts";

function longestBacktickRun(value: string): number {
  let longest = 0;
  let current = 0;
  for (const character of value) {
    if (character === "`") {
      current += 1;
      longest = Math.max(longest, current);
    } else current = 0;
  }
  return longest;
}

function codeSpan(value: string): string {
  const fence = "`".repeat(longestBacktickRun(value) + 1);
  return `${fence}${value}${fence}`;
}

function inline(value: unknown): string {
  if (typeof value === "string") return codeSpan(value.replaceAll(/[\r\n]+/g, " "));
  if (typeof value === "number" || typeof value === "boolean") return codeSpan(String(value));
  return codeSpan("unknown");
}

function object(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function coverage(value: unknown): string {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1 ? `${Math.round(value * 100)}%` : inline(value);
}

function displayRecommendation(value: unknown): string {
  return typeof value === "string" ? value.replaceAll("_", " ") : "unknown";
}

function signalDetail(signal: CompactSignal): string {
  if (!signal.detail) return "";
  const values = Object.entries(signal.detail).map(([key, value]) => {
    if (typeof value === "object") {
      const counts = Object.entries(value).map(([name, count]) => `${inline(name)}=${inline(count)}`).join(",");
      return `${inline(key)}=${counts}`;
    }
    return `${inline(key)}=${inline(value)}`;
  });
  return values.length > 0 ? ` (${values.join(", ")})` : "";
}

function signalMessage(signal: CompactSignal): string {
  switch (signal.code) {
    case "KNOWN_VULNERABILITY": return `${signal.severity} dependency vulnerability observed.`;
    case "KNOWN_EXPLOITED_VULNERABILITY": return "Known exploitation observed through CISA KEV.";
    case "MALICIOUS_PACKAGE_OBSERVED": return "Malicious package observation recorded.";
    case "THREAT_INTELLIGENCE_MATCH": return "Threat-intelligence match observed.";
    case "PROVENANCE_SOURCE_MISMATCH": return "Verified provenance source mismatch observed.";
    case "PROVENANCE_COMMIT_MISMATCH": return "Verified provenance commit mismatch observed.";
    case "MUTABLE_GITHUB_ACTION_REF_OBSERVED": return "GitHub Action uses a mutable reference.";
    case "WORKFLOW_WRITE_PERMISSION_OBSERVED": return "Workflow write permission observed.";
    case "DOWNLOAD_EXECUTE_PATTERN_OBSERVED": return "Download/execute pattern observed.";
    case "INSTALL_LIFECYCLE_SCRIPT_OBSERVED": return "Install lifecycle script observed.";
    case "DEPENDENCY_RESOLUTION_PARTIAL": return "Dependency resolution is incomplete.";
    default: return `${inline(signal.code)} observed from ${inline(signal.source)}${signalDetail(signal)}.`;
  }
}

function strongestSignals(signals: CompactSignal[]): string[] {
  const messages: string[] = [];
  for (const signal of signals) {
    const message = signalMessage(signal);
    if (!messages.includes(message)) messages.push(message);
    if (messages.length >= 6) break;
  }
  return messages;
}

function renderCoverage(result: CompactRiskAssessment, lines: string[]): void {
  const coverageValue = object(result.coverage);
  if (!coverageValue || !Array.isArray(coverageValue.sources)) return;
  lines.push("", "## Evidence Coverage", "");
  for (const source of coverageValue.sources) {
    const item = object(source);
    if (item) lines.push(`- ${inline(item.source)}: ${inline(String(item.status).toLowerCase())}`);
  }
}

function renderRepositorySummary(result: CompactRiskAssessment, lines: string[]): void {
  const summary = result.repositorySummary;
  if (!summary) return;
  lines.push("", "## Dependency Security", "");
  lines.push(`- Exact dependencies resolved: ${inline(summary.dependencies.exact)}`);
  lines.push(`- Unresolved dependencies: ${inline(summary.dependencies.unresolved)}`);
  lines.push(`- Resolution complete: ${inline(summary.dependencies.resolutionComplete)}`);
  lines.push(`- Vulnerabilities: ${inline(summary.vulnerabilities.total)}`);
  lines.push(`  - Critical: ${inline(summary.vulnerabilities.critical)}`);
  lines.push(`  - High: ${inline(summary.vulnerabilities.high)}`);
  lines.push(`  - Medium: ${inline(summary.vulnerabilities.medium)}`);
  lines.push(`  - Low: ${inline(summary.vulnerabilities.low)}`);
  lines.push(`  - Unknown: ${inline(summary.vulnerabilities.unknown)}`);
  lines.push(`  - Highest severity: ${inline(summary.vulnerabilities.highestSeverity ?? "none")}`);
  lines.push(`- CISA KEV matches: ${inline(summary.knownExploitation.kevMatches)} (${String(summary.knownExploitation.status).toLowerCase()})`);
  lines.push(`- MAL-* observations: ${inline(summary.maliciousPackages.observed)}`);

  lines.push("", "## Threat Intelligence", "");
  lines.push(`- Status: ${String(summary.threatIntelligence.status).toLowerCase()}`);
  lines.push(`- Findings: ${inline(summary.threatIntelligence.findings)}`);
  lines.push(`- Highest severity: ${inline(summary.threatIntelligence.highestSeverity ?? "none")}`);

  lines.push("", "## Repository Security Practices", "");
  lines.push(`- Mutable Actions: ${inline(summary.securityPractices.mutableActions)}`);
  lines.push(`- Workflow write permissions: ${inline(summary.securityPractices.workflowWritePermissions)}`);
  lines.push(`- Download/execute findings: ${inline(summary.securityPractices.downloadExecuteFindings)}`);

  lines.push("", "## Provenance", "");
  lines.push(`- Source mismatches: ${inline(summary.provenance.sourceMismatch)}`);
  lines.push(`- Commit mismatches: ${inline(summary.provenance.commitMismatch)}`);
  lines.push(`- Provenance unavailable: ${inline(summary.provenance.unavailable)}`);
}

function renderLimitations(result: CompactRiskAssessment, lines: string[]): void {
  const limitations: string[] = [...result.sourceErrors];
  const summary = result.repositorySummary;
  if (summary && summary.dependencies.unresolved > 0) limitations.push(`${summary.dependencies.unresolved} dependencies could not be resolved exactly.`);
  if (summary && ["UNAVAILABLE", "UNKNOWN", "NOT_CHECKED"].includes(summary.threatIntelligence.status)) limitations.push(`Threat-intelligence source ${summary.threatIntelligence.status.toLowerCase()}.`);
  if (limitations.length === 0) return;
  lines.push("", "## Limitations", "");
  for (const limitation of [...new Set(limitations)].slice(0, 8)) lines.push(`- ${inline(limitation)}`);
  if ((result.omissions.sourceErrorsOmitted ?? 0) > 0) lines.push(`- ${inline(result.omissions.sourceErrorsOmitted)} additional source errors omitted from this report.`);
}

function renderAssessment(result: CompactRiskAssessment): string {
  const subject = object(result.subject);
  const isRepository = subject?.type === "repository";
  const lines: string[] = [isRepository ? "# OMNI Repository Risk Report" : "# OMNI Risk Report", ""];
  if (subject) lines.push(`Subject: ${inline(subject.id)}`);
  lines.push(`Risk Score: ${inline(result.riskScore)} / 100`);
  lines.push(`Recommendation: ${inline(result.recommendation)}`);
  lines.push(`Score Status: ${inline(result.scoreStatus)}`);
  lines.push(`Evidence Status: ${displayRecommendation(result.scoreStatus)}`);
  lines.push(`Evidence Coverage: ${coverage(result.evidenceCoverage)}`);

  const signals = strongestSignals(result.signals);
  lines.push("", "## Why this score", "");
  if (signals.length === 0) lines.push("- No scoring-relevant signals observed.");
  else for (const signal of signals) lines.push(`- ${signal}`);

  if (result.maliciousPackageObservations) {
    lines.push("", "## Malicious Package Observations", "", `- MAL-* observations: ${inline(result.maliciousPackageObservations.observed)}`);
    if (result.maliciousPackageObservations.ids.length > 0) lines.push(`- IDs: ${result.maliciousPackageObservations.ids.map(id => inline(id)).join(", ")}`);
    if ((result.maliciousPackageObservations.idsOmitted ?? 0) > 0) lines.push(`- ${inline(result.maliciousPackageObservations.idsOmitted)} additional MAL-* IDs omitted.`);
  }
  if (isRepository) renderRepositorySummary(result, lines);
  renderCoverage(result, lines);
  renderLimitations(result, lines);

  const preflight = object((result as Record<string, unknown>).preflightContext);
  if (preflight) {
    lines.push("", "## Observed Preflight Context", "");
    if (preflight.resource !== undefined) lines.push(`- Resource: ${inline(preflight.resource)}`);
    const options = Array.isArray(preflight.paymentOptions) ? preflight.paymentOptions : [];
    lines.push(`- Payment options observed: ${inline(options.length)}`);
    lines.push("- This is an observation for caller-side consistency checks, not payment authorization.");
  }

  lines.push("", "## Assessment", "", `Policy: ${inline(result.policyVersion)}`, `Assessed: ${inline(result.assessedAt)}`);
  const freshness = object(result.freshness);
  if (freshness) {
    lines.push(`Freshness oldest: ${inline(freshness.oldestEvidenceAt)}`, `Freshness newest: ${inline(freshness.newestEvidenceAt)}`);
    if (freshness.expiresAt !== undefined) lines.push(`Freshness expires: ${inline(freshness.expiresAt)}`);
  }
  return lines.join("\n");
}

function renderDependencies(result: Record<string, unknown>): string {
  const summary = object(result.summary);
  const lines = ["# OMNI Dependency Risk Report", ""];
  if (summary) {
    lines.push(`Packages assessed: ${inline(summary.count)}`, `Worst risk score: ${inline(summary.worstRiskScore)}`, `Recommendations: ${inline(Object.entries(object(summary.recommendations) ?? {}).map(([key, value]) => `${key}=${value}`).join(", "))}`);
  }
  lines.push("", "## Strongest package findings", "");
  const packages = Array.isArray(result.packages) ? result.packages : [];
  if (packages.length === 0) lines.push("- No package assessments recorded.");
  for (const item of packages.slice(0, 8)) {
    const packageResult = object(item);
    const subject = packageResult ? object(packageResult.subject) : undefined;
    if (packageResult && subject) lines.push(`- ${inline(subject.id)}: score ${inline(packageResult.riskScore)}, ${inline(packageResult.recommendation)}`);
  }
  const omissions = object(result.omissions);
  if (omissions?.packagesOmitted !== undefined) lines.push(`- ${inline(omissions.packagesOmitted)} additional package details omitted.`);
  lines.push("", "## Assessment", "", `Assessed: ${inline(result.assessedAt)}`);
  return lines.join("\n");
}

export function renderRiskMarkdown(result: unknown): string {
  const compact = compactResultForHttp(result);
  if (!object(compact)) return "# OMNI Result\n";
  if (Array.isArray((compact as Record<string, unknown>).packages)) return renderDependencies(compact as Record<string, unknown>);
  return renderAssessment(compact as CompactRiskAssessment);
}
