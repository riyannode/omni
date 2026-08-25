import type { Response } from "express";

export type ResultRepresentation = "json" | "markdown";

const JSON_MEDIA_TYPE = "application/json";
const MARKDOWN_MEDIA_TYPE = "text/markdown";

function quality(value: string): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 && parsed <= 1 ? parsed : 0;
}

function matchSpecificity(range: string, mediaType: string): number {
  if (range === mediaType) return 2;
  if (range === `${mediaType.split("/")[0]}/*`) return 1;
  if (range === "*/*") return 0;
  return -1;
}

function acceptedQuality(accept: string, mediaType: string): { quality: number; specificity: number } {
  let best = { quality: 0, specificity: -1 };
  for (const item of accept.toLowerCase().split(",")) {
    const [rawRange, ...parameters] = item.trim().split(";");
    const range = rawRange?.trim();
    if (!range) continue;
    const parameter = parameters.find(value => value.trim().startsWith("q="));
    const itemQuality = parameter === undefined ? 1 : quality(parameter.trim().slice(2));
    const specificity = matchSpecificity(range, mediaType);
    if (specificity < 0) continue;
    if (specificity > best.specificity || (specificity === best.specificity && itemQuality > best.quality)) {
      best = { quality: itemQuality, specificity };
    }
  }
  return best;
}

export function negotiateResultRepresentation(accept: string | undefined): ResultRepresentation | undefined {
  if (!accept) return "json";
  const json = acceptedQuality(accept, JSON_MEDIA_TYPE);
  const markdown = acceptedQuality(accept, MARKDOWN_MEDIA_TYPE);
  if (json.quality === 0 && markdown.quality === 0) return undefined;
  if (markdown.quality > json.quality) return "markdown";
  return "json";
}

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

function codeBlock(value: string, language: string): string {
  const fence = "`".repeat(Math.max(3, longestBacktickRun(value) + 1));
  return `${fence}${language}\n${value}\n${fence}`;
}

function inline(value: unknown): string {
  const text = typeof value === "string"
    ? value.replaceAll(/[\r\n]+/g, " ")
    : JSON.stringify(value) ?? String(value);
  return codeSpan(text);
}

function object(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function renderRiskSummary(result: Record<string, unknown>, lines: string[]): void {
  const subject = object(result.subject);
  lines.push("# OMNI Risk Assessment", "");
  if (subject) lines.push(`- Subject: ${inline(subject.id)}`, `- Subject type: ${inline(subject.type)}`);
  if (result.policyVersion !== undefined) lines.push(`- Policy version: ${inline(result.policyVersion)}`);
  if (result.recommendation !== undefined) lines.push(`- Recommendation: ${inline(result.recommendation)}`);
  if (result.riskScore !== undefined) lines.push(`- Risk score: ${inline(result.riskScore)}`);
  if (result.evidenceCoverage !== undefined) lines.push(`- Evidence coverage: ${inline(result.evidenceCoverage)}`);
  if (result.assessedAt !== undefined) lines.push(`- Assessed at: ${inline(result.assessedAt)}`);

  const dimensions = object(result.dimensions);
  if (dimensions) {
    lines.push("", "## Risk dimensions", "", "| Dimension | Level |", "| --- | --- |");
    for (const [name, level] of Object.entries(dimensions)) lines.push(`| ${name} | ${inline(level)} |`);
  }

  const signals = Array.isArray(result.signals) ? result.signals : [];
  lines.push("", "## Signals", "");
  if (signals.length === 0) lines.push("No risk signals were recorded.");
  else for (const signal of signals) {
    const item = object(signal);
    if (item) lines.push(`- ${inline(item.code)} (${inline(item.severity)}; source ${inline(item.source)})`);
  }

  const sourceErrors = Array.isArray(result.sourceErrors) ? result.sourceErrors : [];
  lines.push("", "## Source errors", "");
  if (sourceErrors.length === 0) lines.push("No source errors were recorded.");
  else for (const error of sourceErrors) lines.push(`- ${inline(error)}`);

  const freshness = object(result.freshness);
  if (freshness) {
    lines.push("", "## Freshness", "");
    for (const [name, value] of Object.entries(freshness)) lines.push(`- ${name}: ${inline(value)}`);
  }

  const preflightContext = object(result.preflightContext);
  if (preflightContext) {
    lines.push("", "## Observed preflight context", "");
    if (preflightContext.resource !== undefined) lines.push(`- Resource: ${inline(preflightContext.resource)}`);
    const options = Array.isArray(preflightContext.paymentOptions) ? preflightContext.paymentOptions : [];
    lines.push(`- Payment options observed: ${inline(options.length)}`);
  }
}

function renderDependencySummary(result: Record<string, unknown>, lines: string[]): void {
  const summary = object(result.summary);
  lines.push("# OMNI Dependency Assessment", "");
  if (summary) {
    if (summary.count !== undefined) lines.push(`- Packages: ${inline(summary.count)}`);
    if (summary.worstRiskScore !== undefined) lines.push(`- Worst risk score: ${inline(summary.worstRiskScore)}`);
  }
  const packages = Array.isArray(result.packages) ? result.packages : [];
  if (packages.length > 0) {
    lines.push("", "## Package assessments", "");
    for (const packageResult of packages) {
      const item = object(packageResult);
      const subject = item ? object(item.subject) : undefined;
      if (item && subject) {
        lines.push(`- Subject: ${inline(subject.id)}`, `  - Risk score: ${inline(item.riskScore)}`, `  - Recommendation: ${inline(item.recommendation)}`);
      }
    }
  }
}

export function renderResultAsMarkdown(result: unknown): string {
  const record = object(result);
  const lines: string[] = [];
  if (record?.subject !== undefined) renderRiskSummary(record, lines);
  else if (record?.packages !== undefined && record?.summary !== undefined) renderDependencySummary(record, lines);
  else lines.push("# OMNI Result", "");

  const canonicalJson = JSON.stringify(result, null, 2) ?? "null";
  lines.push("", "## Canonical JSON", "", codeBlock(canonicalJson, "json"), "");
  return lines.join("\n");
}

export function sendResult(res: Response, status: number, result: unknown, accept: string | undefined): void {
  res.vary("Accept");
  const representation = negotiateResultRepresentation(accept);
  if (representation === undefined) {
    res.status(406).json({ error: "not_acceptable", retryable: false });
    return;
  }
  if (representation === "markdown") {
    res.status(status).type(MARKDOWN_MEDIA_TYPE).send(renderResultAsMarkdown(result));
    return;
  }
  res.status(status).json(result);
}
