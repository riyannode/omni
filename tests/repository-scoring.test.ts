import { describe, expect, test } from "bun:test";
import { extractRiskFeatures } from "../src/domain/risk-features.ts";
import { DEFAULT_RISK_POLICY, RISK_POLICY_VERSION } from "../src/domain/risk-policy.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
import type { ExactDependencyCoordinate, RepositoryEvidence, RiskSnapshot, ThreatFinding } from "../src/domain/risk.ts";

const engine = new RiskEngine();
const coordinate: ExactDependencyCoordinate = { ecosystem: "NPM", name: "demo", version: "1.0.0", sourcePath: "package-lock.json", manifestPath: "package.json", workspacePath: "." };
const evidence = { source: "fixture", kind: "repository", observedAt: "2026-01-01T00:00:00.000Z", detail: {} };

function repositoryEvidence(overrides: Partial<RepositoryEvidence> = {}): RepositoryEvidence {
  return {
    target: { repository: "github.com/acme/demo", resolvedCommitSha: "0123456789abcdef0123456789abcdef01234567" },
    securityFiles: [],
    dependencies: { exact: [], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } },
    dependencyObservations: [],
    dependencyVulnerabilities: { status: "NOT_CHECKED", packagesInspected: [], findings: [], maliciousPackageObservations: [], summary: { status: "NOT_CHECKED", findingsObserved: 0, countsBySeverity: { unknown: 0, low: 0, medium: 0, high: 0, critical: 0 }, knownExploitedObserved: 0, maliciousPackageObservationsObserved: 0 }, cisaKev: { status: "NOT_QUERIED", correlatableCveIds: [], matchedCveIds: [] }, errors: [], limitations: [] },
    dependencyThreatIntel: { status: "NOT_CHECKED", packagesInspected: [], findings: [], summary: { status: "NOT_CHECKED", findingsObserved: 0, countsBySeverity: { low: 0, medium: 0, high: 0, critical: 0 } }, errors: [], limitations: [] },
    coverage: { status: "complete", treeEntriesInspected: 1, filesInspected: 1, bytesInspected: 1, limitations: [] },
    sourceErrors: [],
    ...overrides
  };
}

function fullCoverage(overrides: Record<string, "OBSERVED" | "ABSENT" | "UNKNOWN" | "UNAVAILABLE" | "NOT_APPLICABLE"> = {}): NonNullable<RiskSnapshot["coverage"]> {
  return {
    modelVersion: "repository-coverage-v1",
    sources: [
      { source: "GitHub Repository Evidence", execution: (overrides.github ?? "OBSERVED") === "NOT_APPLICABLE" ? "NOT_QUERIED" : "QUERIED", status: overrides.github ?? "OBSERVED", weight: 1 },
      { source: "OpenSSF Scorecard", execution: (overrides.scorecard ?? "OBSERVED") === "NOT_APPLICABLE" ? "NOT_QUERIED" : "QUERIED", status: overrides.scorecard ?? "OBSERVED", weight: 1 },
      { source: "Dependency Resolution", execution: "NOT_QUERIED", status: overrides.resolution ?? "NOT_APPLICABLE", weight: 1 },
      { source: "OSV Dependency Vulnerabilities", execution: (overrides.osv ?? "NOT_APPLICABLE") === "NOT_APPLICABLE" ? "NOT_QUERIED" : "QUERIED", status: overrides.osv ?? "NOT_APPLICABLE", weight: 1 },
      { source: "CISA KEV", execution: (overrides.kev ?? "NOT_APPLICABLE") === "NOT_APPLICABLE" ? "NOT_QUERIED" : "QUERIED", status: overrides.kev ?? "NOT_APPLICABLE", weight: 1 },
      { source: "deps.dev Provenance", execution: (overrides.provenance ?? "NOT_APPLICABLE") === "NOT_APPLICABLE" ? "NOT_QUERIED" : "QUERIED", status: overrides.provenance ?? "NOT_APPLICABLE", weight: 1 },
      { source: "Threat Intelligence", execution: (overrides.threat ?? "NOT_APPLICABLE") === "NOT_APPLICABLE" ? "NOT_QUERIED" : "QUERIED", status: overrides.threat ?? "NOT_APPLICABLE", weight: 1 }
    ]
  };
}

function snapshot(options: { scorecard?: number; repository?: RepositoryEvidence; coverage?: RiskSnapshot["coverage"] }): RiskSnapshot {
  const coverage = options.coverage ?? fullCoverage();
  return { subject: { type: "repository", id: "github.com/acme/demo" }, ...(options.scorecard === undefined ? {} : { scorecard: options.scorecard }), ...(options.repository ? { repositoryEvidence: options.repository } : {}), coverage, evidence: [evidence] };
}

function vulnerability(severity: "unknown" | "low" | "medium" | "high" | "critical", knownExploited = false) {
  return { coordinate, vulnerability: { id: `CVE-${severity}`, severity, knownExploited, aliases: [] }, sources: [knownExploited ? "CISA KEV" : "OSV"] as ["OSV"] };
}

function scoredVulnerability(severity: "unknown" | "low" | "medium" | "high" | "critical", knownExploited = false): RepositoryEvidence {
  const finding = vulnerability(severity, knownExploited);
  return repositoryEvidence({ dependencies: { exact: [coordinate], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } }, dependencyVulnerabilities: { status: "CHECKED", packagesInspected: [coordinate], findings: [finding], maliciousPackageObservations: [], summary: { status: "VALID", findingsObserved: 1, countsBySeverity: { unknown: severity === "unknown" ? 1 : 0, low: severity === "low" ? 1 : 0, medium: severity === "medium" ? 1 : 0, high: severity === "high" ? 1 : 0, critical: severity === "critical" ? 1 : 0 }, knownExploitedObserved: knownExploited ? 1 : 0, maliciousPackageObservationsObserved: 0 }, cisaKev: { status: knownExploited ? "CHECKED" : "NOT_QUERIED", correlatableCveIds: knownExploited ? [`CVE-${severity}`] : [], matchedCveIds: knownExploited ? [`CVE-${severity}`] : [] }, errors: [], limitations: [] } });
}

describe("deterministic repository scoring", () => {
  test("keeps the versioned repository policy exact and frozen", () => {
    expect(RISK_POLICY_VERSION).toBe("omni-risk-v3");
    expect(DEFAULT_RISK_POLICY.repository).toEqual({ scorecardMaximum: 10, scorecardRiskMultiplier: 6, installLifecycleScript: 10, mutableGithubActionRef: 35, workflowWritePermission: 35, downloadExecutePattern: 60, provenanceSourceMismatch: 60, provenanceCommitMismatch: 60, knownExploitation: 90, maliciousPackageObservation: 100 });
  });

  test.each([
    ["clean strong repository", 9.5, [], 3, "proceed"],
    ["mutable action only", 9.5, [{ path: ".github/workflows/ci.yml", category: "workflow", status: "inspected", findings: ["MUTABLE_GITHUB_ACTION_REF"] }], 35, "proceed_with_caution"],
    ["workflow write permission only", 9.5, [{ path: ".github/workflows/ci.yml", category: "workflow", status: "inspected", findings: ["WORKFLOW_WRITE_PERMISSION"] }], 35, "proceed_with_caution"],
    ["download execute", 9.5, [{ path: "install.sh", category: "build", status: "inspected", findings: ["DOWNLOAD_EXECUTE_PATTERN"] }], 60, "manual_review"],
    ["scorecard zero", 0, [], 60, "manual_review"]
  ] as const)("scores %s by strongest observed practice", (_name, scorecard, securityFiles, score, recommendation) => {
    const result = engine.assess(snapshot({ scorecard, repository: repositoryEvidence({ securityFiles: securityFiles.map(file => ({ ...file, findings: [...file.findings] })) as unknown as RepositoryEvidence["securityFiles"] }) }));
    expect({ riskScore: result.riskScore, recommendation: result.recommendation }).toEqual({ riskScore: score, recommendation });
  });

  test.each([
    ["source mismatch", "VERIFIED_SOURCE_MISMATCH" as const],
    ["commit mismatch", "VERIFIED_COMMIT_MISMATCH" as const]
  ])("scores provenance %s", (_name, state) => {
    const result = engine.assess(snapshot({ scorecard: 9.5, repository: repositoryEvidence({ dependencies: { exact: [coordinate], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } }, dependencyObservations: [{ coordinate, licenses: [], advisoryIds: [], graph: { checked: true, nodeCount: 1 }, provenance: [{ package: coordinate, state, source: "deps.dev" }] }] }) }));
    expect(result.riskScore).toBe(60);
    expect(result.recommendation).toBe("manual_review");
  });

  test.each([
    ["unknown", 30, "proceed_with_caution", "unknown"],
    ["low", 10, "proceed", "low"],
    ["medium", 35, "proceed_with_caution", "medium"],
    ["high", 60, "manual_review", "high"],
    ["critical", 85, "do_not_proceed", "critical"]
  ] as const)("scores %s vulnerability", (severity, score, recommendation, dimension) => {
    const result = engine.assess(snapshot({ scorecard: 9.5, repository: scoredVulnerability(severity) }));
    expect({ riskScore: result.riskScore, recommendation: result.recommendation, knownVulnerabilities: result.dimensions.knownVulnerabilities }).toEqual({ riskScore: score, recommendation, knownVulnerabilities: dimension });
  });

  test.each(["NPM", "CARGO", "PYPI", "GO"] as const)("uses the same high-vulnerability score for %s", ecosystem => {
    const item = { ...coordinate, ecosystem };
    const result = engine.assess(snapshot({ scorecard: 9.5, repository: repositoryEvidence({ dependencies: { exact: [item], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } }, dependencyVulnerabilities: { status: "CHECKED", packagesInspected: [item], findings: [{ coordinate: item, vulnerability: { id: `CVE-${ecosystem}`, severity: "high", knownExploited: false, aliases: [] }, sources: ["OSV"] }], maliciousPackageObservations: [], summary: { status: "VALID", findingsObserved: 1, countsBySeverity: { unknown: 0, low: 0, medium: 0, high: 1, critical: 0 }, knownExploitedObserved: 0, maliciousPackageObservationsObserved: 0 }, cisaKev: { status: "NOT_QUERIED", correlatableCveIds: [], matchedCveIds: [] }, errors: [], limitations: [] } }) }));
    expect(result.riskScore).toBe(60);
  });

  test("scores KEV independently of vulnerability severity", () => {
    const result = engine.assess(snapshot({ scorecard: 9.5, repository: scoredVulnerability("high", true), coverage: fullCoverage({ osv: "OBSERVED", kev: "OBSERVED" }) }));
    expect(result.riskScore).toBe(90);
    expect(result.recommendation).toBe("do_not_proceed");
    expect(result.dimensions.knownExploitation).toBe("critical");
    expect(result.signals.some(signal => signal.code === "KNOWN_EXPLOITED_VULNERABILITY" && signal.source === "CISA KEV")).toBe(true);
  });

  test("scores active MAL observations without converting them to vulnerabilities", () => {
    const result = engine.assess(snapshot({ scorecard: 9.5, repository: repositoryEvidence({ dependencies: { exact: [coordinate], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } }, dependencyVulnerabilities: { status: "CHECKED", packagesInspected: [coordinate], findings: [], maliciousPackageObservations: [{ coordinate, id: "MAL-2026-0001", source: "OSV" }], summary: { status: "VALID", findingsObserved: 0, countsBySeverity: { unknown: 0, low: 0, medium: 0, high: 0, critical: 0 }, knownExploitedObserved: 0, maliciousPackageObservationsObserved: 1 }, cisaKev: { status: "NOT_QUERIED", correlatableCveIds: [], matchedCveIds: [] }, errors: [], limitations: [] } }) }));
    expect(result.riskScore).toBe(100);
    expect(result.recommendation).toBe("do_not_proceed");
    expect(result.signals).toContainEqual({ code: "MALICIOUS_PACKAGE_OBSERVED", severity: "critical", source: "OSV", detail: { ecosystem: "NPM", name: "demo", version: "1.0.0", id: "MAL-2026-0001" } });
    expect(result.dimensions.knownVulnerabilities).toBe("low");
  });

  test.each([
    ["medium", 60, "manual_review"],
    ["critical", 100, "do_not_proceed"]
  ] as const)("scores %s dependency threat intelligence", (severity, score, recommendation) => {
    const finding: ThreatFinding = { indicatorType: "package", indicator: "NPM:demo@1.0.0", threatType: "malicious_package", severity, source: "licensed-feed" };
    const result = engine.assess(snapshot({ scorecard: 9.5, repository: repositoryEvidence({ dependencies: { exact: [coordinate], unresolved: [], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } }, dependencyThreatIntel: { status: "CHECKED", packagesInspected: [coordinate], findings: [{ coordinate, finding }], summary: { status: "VALID", findingsObserved: 1, countsBySeverity: { low: 0, medium: severity === "medium" ? 1 : 0, high: 0, critical: severity === "critical" ? 1 : 0 }, }, errors: [], limitations: [] } }) }));
    expect({ riskScore: result.riskScore, recommendation: result.recommendation, maliciousInfrastructure: result.dimensions.maliciousInfrastructure }).toEqual({ riskScore: score, recommendation, maliciousInfrastructure: severity === "medium" ? "high" : "critical" });
  });

  test("uses MAX aggregation rather than adding findings", () => {
    const result = engine.assess(snapshot({ scorecard: 5, repository: repositoryEvidence({ securityFiles: [{ path: "ci.yml", category: "workflow", status: "inspected", findings: ["MUTABLE_GITHUB_ACTION_REF", "WORKFLOW_WRITE_PERMISSION", "DOWNLOAD_EXECUTE_PATTERN"] }], dependencyVulnerabilities: scoredVulnerability("high").dependencyVulnerabilities }) }));
    expect(result.riskScore).toBe(60);
  });

  test("keeps high observed risk when coverage is partial", () => {
    const result = engine.assess(snapshot({ scorecard: 9.5, repository: scoredVulnerability("critical"), coverage: fullCoverage({ osv: "UNKNOWN", kev: "UNKNOWN" }) }));
    expect(result.riskScore).toBe(85);
    expect(result.recommendation).toBe("do_not_proceed");
    expect(result.scoreStatus).toBe("measured_partial");
  });

  test("does not add score for source failure, unresolved, or deferred uncertainty", () => {
    const clean = engine.assess(snapshot({ scorecard: 9.5, repository: repositoryEvidence() }));
    const uncertain = engine.assess(snapshot({ scorecard: 9.5, repository: repositoryEvidence({ dependencies: { exact: [], unresolved: [{ ecosystem: "NPM", name: "unknown", requirement: "^1", manifestPath: "package.json", workspacePath: "." }], resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } }, coverage: { status: "partial", treeEntriesInspected: 1, filesInspected: 1, bytesInspected: 1, limitations: ["dependency_enrichment_limit_reached:1_of_25_deferred"] } }), coverage: fullCoverage({ resolution: "UNKNOWN", osv: "UNKNOWN", kev: "UNKNOWN", provenance: "UNKNOWN", threat: "UNKNOWN" }) }));
    expect(uncertain.riskScore).toBe(clean.riskScore);
    expect(uncertain.recommendation).toBe("manual_review");
  });

  test("fails closed for invalid summaries while preserving retained strong evidence", () => {
    const retained = scoredVulnerability("critical");
    retained.dependencyVulnerabilities.summary = { status: "INCONSISTENT", findingsObserved: 99, countsBySeverity: { unknown: 0, low: 0, medium: 0, high: 0, critical: 99 }, knownExploitedObserved: 0, maliciousPackageObservationsObserved: 0 };
    const result = engine.assess(snapshot({ scorecard: 9.5, repository: retained }));
    expect(result.riskScore).toBe(85);
    expect(result.dimensions.knownVulnerabilities).toBe("critical");
    expect(result.scoreStatus).toBe("measured_partial");
    expect(result.recommendation).toBe("do_not_proceed");
  });

  test("summary validity distinguishes missing, not-checked, and valid zero", () => {
    const validZero = extractRiskFeatures(snapshot({ scorecard: 9.5, repository: repositoryEvidence() }));
    expect(validZero.repository.dependencyVulnerabilitySummaryStatus).toBe("NOT_CHECKED");
    expect(validZero.repository.dependencyVulnerabilitySummaryValid).toBe(false);
    const missingEvidence = repositoryEvidence();
    const missingObservation = { ...missingEvidence.dependencyVulnerabilities };
    delete missingObservation.summary;
    missingEvidence.dependencyVulnerabilities = missingObservation;
    const missing = extractRiskFeatures(snapshot({ scorecard: 9.5, repository: missingEvidence }));
    expect(missing.repository.dependencyVulnerabilitySummaryStatus).toBe("MISSING");
    expect(missing.repository.dependencyVulnerabilitySummaryValid).toBe(false);
    const checkedZero = repositoryEvidence({ dependencyVulnerabilities: { ...repositoryEvidence().dependencyVulnerabilities, status: "CHECKED", summary: { status: "VALID", findingsObserved: 0, countsBySeverity: { unknown: 0, low: 0, medium: 0, high: 0, critical: 0 }, knownExploitedObserved: 0, maliciousPackageObservationsObserved: 0 } } });
    const checkedFeatures = extractRiskFeatures(snapshot({ scorecard: 9.5, repository: checkedZero }));
    expect(checkedFeatures.repository.dependencyVulnerabilitySummaryValid).toBe(true);
  });

  test("is deterministic under reverse input order", () => {
    const left = repositoryEvidence({ securityFiles: [{ path: "z.yml", category: "workflow", status: "inspected", findings: ["MUTABLE_GITHUB_ACTION_REF"] }, { path: "a.sh", category: "build", status: "inspected", findings: ["DOWNLOAD_EXECUTE_PATTERN"] }], dependencyVulnerabilities: { ...scoredVulnerability("high").dependencyVulnerabilities, findings: [vulnerability("high"), vulnerability("medium")] } });
    const right = structuredClone(left);
    right.securityFiles.reverse();
    right.dependencyVulnerabilities.findings.reverse();
    expect(engine.assess(snapshot({ scorecard: 9.5, repository: left })).signals).toEqual(engine.assess(snapshot({ scorecard: 9.5, repository: right })).signals);
  });

  test("keeps repository-only dimensions not applicable", () => {
    const result = engine.assess(snapshot({ scorecard: 9.5, repository: repositoryEvidence() }));
    expect(result.dimensions).toMatchObject({ packageSupplyChain: "not_applicable", serviceIdentity: "not_applicable", paymentConfigurationRisk: "not_applicable", endpointOperationalRisk: "not_applicable" });
  });
});
