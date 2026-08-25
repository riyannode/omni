function longestBacktickRun(value: string): number {
  let longest = 0;
  let current = 0;
  for (const character of value) {
    if (character === "`") {
      current += 1;
      longest = Math.max(longest, current);
    } else {
      current = 0;
    }
  }
  return longest;
}

function codeSpan(value: string): string {
  const fence = "`".repeat(longestBacktickRun(value) + 1);
  return `${fence}${value}${fence}`;
}

function inline(value: unknown): string {
  const text = typeof value === "string"
    ? value.replaceAll(/[\r\n]+/g, " ")
    : JSON.stringify(value) ?? String(value);
  return codeSpan(text);
}

function coverage(value: unknown): string {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1
    ? `${Math.round(value * 100)}%`
    : inline(value);
}

function object(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function renderRiskSummary(result: Record<string, unknown>, lines: string[]): void {
  const subject = object(result.subject);
  lines.push("# OMNI Risk Assessment", "");
  if (subject) lines.push(`Subject: ${inline(subject.id)}`, `Subject Type: ${inline(subject.type)}`);
  if (result.policyVersion !== undefined) lines.push(`Policy Version: ${inline(result.policyVersion)}`);
  if (result.recommendation !== undefined) lines.push(`Recommendation: ${inline(result.recommendation)}`);
  if (result.riskScore !== undefined) lines.push(`Risk Score: ${inline(result.riskScore)} / 100`);
  if (result.evidenceCoverage !== undefined) lines.push(`Evidence Coverage: ${coverage(result.evidenceCoverage)}`);
  if (result.assessedAt !== undefined) lines.push(`Assessed At: ${inline(result.assessedAt)}`);

  const dimensions = object(result.dimensions);
  if (dimensions) {
    lines.push("", "## Risk Dimensions", "");
    for (const [name, level] of Object.entries(dimensions)) lines.push(`- ${name}: ${inline(level)}`);
  }

  const signals = Array.isArray(result.signals) ? result.signals : [];
  lines.push("", "## Key Signals", "");
  if (signals.length === 0) lines.push("No risk signals were recorded.");
  else for (const signal of signals) {
    const item = object(signal);
    if (item) lines.push(`- Code: ${inline(item.code)}; Severity: ${inline(item.severity)}; Source: ${inline(item.source)}; Detail: ${inline(item.detail)}`);
  }

  const evidence = Array.isArray(result.evidence) ? result.evidence : [];
  lines.push("", "## Evidence", "");
  if (evidence.length === 0) lines.push("No evidence was recorded.");
  else for (const item of evidence) {
    const evidenceItem = object(item);
    if (evidenceItem) lines.push(`- Source: ${inline(evidenceItem.source)}; Kind: ${inline(evidenceItem.kind)}; Observed At: ${inline(evidenceItem.observedAt)}; Detail: ${inline(evidenceItem.detail)}`);
  }

  const sourceErrors = Array.isArray(result.sourceErrors) ? result.sourceErrors : [];
  lines.push("", "## Source Errors", "");
  if (sourceErrors.length === 0) lines.push("No source errors were recorded.");
  else for (const error of sourceErrors) lines.push(`- ${inline(error)}`);

  const freshness = object(result.freshness);
  if (freshness) {
    lines.push("", "## Freshness", "");
    for (const [name, value] of Object.entries(freshness)) lines.push(`- ${name}: ${inline(value)}`);
  }

  const preflightContext = object(result.preflightContext);
  if (preflightContext) {
    lines.push("", "## Observed Preflight Context", "");
    if (preflightContext.resource !== undefined) lines.push(`- Resource: ${inline(preflightContext.resource)}`);
    const options = Array.isArray(preflightContext.paymentOptions) ? preflightContext.paymentOptions : [];
    lines.push(`- Payment Options Observed: ${inline(options.length)}`);
    lines.push("- This is an observation for caller-side consistency checks, not payment authorization.");
    for (const option of options) lines.push(`- Observed Option: ${inline(option)}`);
  }
}

function renderDependencySummary(result: Record<string, unknown>, lines: string[]): void {
  const summary = object(result.summary);
  lines.push("# OMNI Dependency Assessment", "");
  if (summary) {
    if (summary.count !== undefined) lines.push(`Packages: ${inline(summary.count)}`);
    if (summary.worstRiskScore !== undefined) lines.push(`Worst Risk Score: ${inline(summary.worstRiskScore)}`);
    if (summary.recommendations !== undefined) lines.push(`Recommendations: ${inline(summary.recommendations)}`);
  }
  const packages = Array.isArray(result.packages) ? result.packages : [];
  lines.push("", "## Package Assessments", "");
  if (packages.length === 0) lines.push("No package assessments were recorded.");
  for (const packageResult of packages) {
    const item = object(packageResult);
    const subject = item ? object(item.subject) : undefined;
    if (item && subject) {
      lines.push(`- Subject: ${inline(subject.id)}`, `  - Risk Score: ${inline(item.riskScore)}`, `  - Recommendation: ${inline(item.recommendation)}`);
    }
  }
}

export function renderRiskMarkdown(result: unknown): string {
  const record = object(result);
  const lines: string[] = [];
  if (record?.subject !== undefined) renderRiskSummary(record, lines);
  else if (record?.packages !== undefined && record?.summary !== undefined) renderDependencySummary(record, lines);
  else lines.push("# OMNI Result", "");

  return lines.join("\n");
}
