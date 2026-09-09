import { describe, expect, test } from "bun:test";
import type { Response } from "express";
import { compactResultForHttp, MAX_PUBLIC_MARKDOWN_BYTES, MAX_PUBLIC_JSON_BYTES, sendResult } from "../src/http/result-representation.ts";
import { renderRiskMarkdown } from "../src/http/risk-markdown.ts";

function repositoryResult() {
  return {
    subject: { type: "repository", id: "github.com/owner/repo" },
    policyVersion: "omni-risk-v3",
    scoreStatus: "measured_partial",
    recommendation: "manual_review",
    riskScore: 60,
    evidenceCoverage: 0.82,
    dimensions: {
      knownVulnerabilities: "high",
      knownExploitation: "low",
      packageSupplyChain: "not_applicable",
      repositorySecurityPractices: "medium",
      maliciousInfrastructure: "unknown",
      serviceIdentity: "not_applicable",
      paymentConfigurationRisk: "not_applicable",
      endpointOperationalRisk: "not_applicable"
    },
    signals: Array.from({ length: 48 }, (_, index) => ({
      code: index === 0 ? "KNOWN_VULNERABILITY" : `SIGNAL_${index}`,
      severity: index < 3 ? "critical" : index < 12 ? "high" : "low",
      source: "fixture",
      detail: { id: `CVE-${index}`, rawProviderPayload: "x".repeat(2_000), count: index + 1 }
    })),
    evidence: Array.from({ length: 40 }, (_, index) => ({
      source: "provider",
      kind: "raw_detail",
      observedAt: "2026-09-10T00:00:00.000Z",
      detail: { index, rawProviderPayload: "evidence".repeat(4_000) }
    })),
    repositorySummary: {
      dependencies: { exact: 42, unresolved: 3, resolutionComplete: false },
      vulnerabilities: { total: 5, unknown: 0, low: 1, medium: 2, high: 2, critical: 0, highestSeverity: "high" },
      knownExploitation: { kevMatches: 0, status: "CHECKED" },
      maliciousPackages: { observed: 0 },
      threatIntelligence: { status: "UNAVAILABLE", findings: 0, highestSeverity: null },
      provenance: { sourceMismatch: 0, commitMismatch: 1, unavailable: 2 },
      securityPractices: { mutableActions: 1, workflowWritePermissions: 0, downloadExecuteFindings: 0 }
    },
    coverage: {
      modelVersion: "repository-coverage-v1",
      resolvedWeight: 7,
      applicableWeight: 8,
      sources: [
        { source: "GitHub Repository Evidence", execution: "QUERIED", status: "OBSERVED", weight: 1 },
        { source: "Dependency Resolution", execution: "QUERIED", status: "UNKNOWN", weight: 1 },
        { source: "Threat Intelligence", execution: "QUERIED", status: "UNAVAILABLE", weight: 1 }
      ]
    },
    sourceErrors: ["Threat Intelligence: feed unavailable"],
    assessedAt: "2026-09-10T00:00:00.000Z",
    freshness: { oldestEvidenceAt: "2026-09-10T00:00:00.000Z", newestEvidenceAt: "2026-09-10T00:00:00.000Z" }
  };
}

function responseCapture(): { response: Response; state: { status: number; body: unknown } } {
  const state = { status: 0, body: undefined as unknown };
  const response = {
    headersSent: false,
    vary() { return response; },
    status(status: number) { state.status = status; return response; },
    type() { return response; },
    send(body: unknown) { state.body = body; return response; },
    json(body: unknown) { state.body = body; return response; }
  } as unknown as Response;
  return { response, state };
}

describe("compact HTTP representations", () => {
  test("returns a bounded agent assessment without artifact, raw evidence, or provider payloads", () => {
    const compact = compactResultForHttp(repositoryResult()) as Record<string, unknown>;
    expect(compact).not.toHaveProperty("artifact");
    expect(compact).not.toHaveProperty("evidence");
    expect(compact).toMatchObject({
      subject: { type: "repository", id: "github.com/owner/repo" },
      policyVersion: "omni-risk-v3",
      scoreStatus: "measured_partial",
      recommendation: "manual_review",
      riskScore: 60,
      evidenceCoverage: 0.82,
      repositorySummary: { vulnerabilities: { high: 2, highestSeverity: "high" }, knownExploitation: { kevMatches: 0 }, threatIntelligence: { status: "UNAVAILABLE" } },
      omissions: { evidenceDetailsOmitted: 40, dependencyDetailsOmitted: 45, signalsOmitted: 16 }
    });
    expect(JSON.stringify(compact)).not.toContain("rawProviderPayload");
    expect(Buffer.byteLength(JSON.stringify(compact))).toBeLessThan(MAX_PUBLIC_JSON_BYTES);
  });

  test("renders deterministic human Markdown from the same compact assessment", () => {
    const first = renderRiskMarkdown(repositoryResult());
    const second = renderRiskMarkdown(repositoryResult());
    expect(first).toBe(second);
    expect(first).toContain("# OMNI Repository Risk Report");
    expect(first).toContain("Risk Score: `60` / 100");
    expect(first).toContain("Recommendation: `manual_review`");
    expect(first).toContain("critical dependency vulnerability observed.");
    expect(first).toContain("CISA KEV matches: `0`");
    expect(first).toContain("- `Threat Intelligence`: `unavailable`");
    expect(first).not.toContain("rawProviderPayload");
    expect(first).not.toContain("raw_detail");
    expect(first).not.toContain("JSON.stringify");
    expect(Buffer.byteLength(first)).toBeLessThan(MAX_PUBLIC_MARKDOWN_BYTES);
  });

  test("counts invalid signals as explicit omissions", () => {
    const result = repositoryResult() as unknown as { signals: unknown[]; coverage: { sources: Array<{ source: string }> } } & Record<string, unknown>;
    result.signals = [null, { code: "bad", severity: "invalid", source: "fixture", detail: {} }, result.signals[0]];
    const compact = compactResultForHttp(result) as Record<string, unknown>;
    expect(compact).toMatchObject({ omissions: { signalsOmitted: 2 }, signals: [{ code: "KNOWN_VULNERABILITY" }] });
  });

  test("escapes provider-derived Markdown values", () => {
    const result = repositoryResult();
    result.coverage.sources[0]!.source = "provider **[unsafe]`";
    const markdown = renderRiskMarkdown(result);
    expect(markdown).toContain("provider **[unsafe]`");
    const coverageLine = markdown.split("\n").find(line => line.includes("provider **[unsafe]"));
    expect(coverageLine?.startsWith("- ``provider **[unsafe]")).toBe(true);
  });

  test("fails closed instead of emitting an oversized representation", () => {
    const result = { ...repositoryResult(), subject: { type: "repository", id: "x".repeat(MAX_PUBLIC_JSON_BYTES + 1) } };
    const jsonCapture = responseCapture();
    sendResult(jsonCapture.response, 200, result, "json", "repository");
    expect(jsonCapture.state).toEqual({ status: 500, body: { error: "response_representation_too_large", retryable: false } });

    const markdownCapture = responseCapture();
    sendResult(markdownCapture.response, 200, result, "markdown", "repository");
    expect(markdownCapture.state).toEqual({ status: 500, body: { error: "response_representation_too_large", retryable: false } });
  });

  test("reports coverage and payment-option truncation in JSON and Markdown", () => {
    const result = repositoryResult() as unknown as Record<string, any>;
    result.coverage.sources = Array.from({ length: 20 }, (_, index) => ({ source: `source-${index}`, execution: "QUERIED", status: "OBSERVED", weight: 1 }));
    result.subject = { type: "x402_endpoint", id: "https://example.com/paid" };
    result.preflightContext = {
      resource: "https://example.com/paid",
      paymentOptions: Array.from({ length: 10 }, (_, index) => ({ scheme: "exact", network: `network-${index}`, amount: "5000", asset: "USDC", payTo: "0x1111111111111111111111111111111111111111" }))
    };
    const compact = compactResultForHttp(result) as Record<string, any>;
    expect(compact.omissions).toMatchObject({ coverageSourcesOmitted: 4, paymentOptionsOmitted: 2 });
    expect(compact.preflightContext.paymentOptions).toHaveLength(8);
    const markdown = renderRiskMarkdown(result);
    expect(markdown).toContain("4 coverage sources omitted");
    expect(markdown).toContain("2 payment options omitted");
  });

  test("preserves omission metadata and MAL IDs when compacted twice", () => {
    const result = repositoryResult() as unknown as Record<string, any>;
    result.maliciousPackageObservations = Array.from({ length: 20 }, (_, index) => ({ id: `MAL-${index}`, package: {}, queriedVersion: "1.0.0" }));
    const once = compactResultForHttp(result) as Record<string, any>;
    const twice = compactResultForHttp(once) as Record<string, any>;
    expect(twice.maliciousPackageObservations).toEqual(once.maliciousPackageObservations);
    expect(twice.omissions).toEqual(once.omissions);
  });

  test("Markdown discloses evidence, dependency, signal, and package omissions", () => {
    const markdown = renderRiskMarkdown(repositoryResult());
    expect(markdown).toContain("40 evidence details omitted");
    expect(markdown).toContain("45 dependency details omitted");
    expect(markdown).toContain("`42` scoring signals omitted");

    const dependencyResult = {
      packages: Array.from({ length: 20 }, (_, index) => ({ ...repositoryResult(), subject: { type: "package", id: `npm:pkg-${index}@1.0.0` } })),
      summary: { count: 20, worstRiskScore: 60, recommendations: { manual_review: 20 } },
      assessedAt: "2026-09-10T00:00:00.000Z"
    };
    expect(renderRiskMarkdown(dependencyResult)).toContain("`4` additional package details omitted");
  });
});
