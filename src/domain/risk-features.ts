import type { ProvenanceState, RiskLevel, RiskSnapshot, ThreatFinding, VulnerabilityFinding } from "./risk.ts";

export const RISK_FEATURE_SCHEMA_VERSION = 2 as const;

export type RiskFeatures = {
  schemaVersion: typeof RISK_FEATURE_SCHEMA_VERSION;
  subject: RiskSnapshot["subject"];
  vulnerabilities: VulnerabilityFinding[] | undefined;
  vulnerabilityCount: number;
  knownExploitedVulnerabilityCount: number;
  maximumVulnerabilitySeverity: RiskLevel | undefined;
  exploitationChecked: boolean;
  package: { present: boolean; deprecated: boolean; installLifecycleScript: boolean; integrityPresent: boolean; maintainerCount: number | undefined };
  repository: { present: boolean; partial: boolean; installLifecycleScriptCount: number; downloadExecutePatternCount: number; mutableActionRefCount: number; workflowWritePermissionCount: number; exactDependencyCount: number; unresolvedDependencyCount: number; provenanceStates: Record<ProvenanceState, number> };
  scorecard: number | undefined;
  threatIntel: { checked: boolean; findings: ThreatFinding[]; matchCount: number; countsBySeverity: Record<Exclude<RiskLevel, "unknown">, number> };
  endpoint: { present: boolean; listedOnCircle: boolean | undefined; supportsGateway: boolean | undefined; supportsVanilla: boolean | undefined; responseStatus: number | undefined };
  history: { checked: boolean; present: boolean; payToChangeCount: number; networkChangeCount: number; priceChangeCount: number; schemaChangeCount: number; providerChangeCount: number };
  sourceErrorCount: number;
  coverage: { completed: number; expected: number };
  evidenceCount: number;
};

export function extractRiskFeatures(snapshot: RiskSnapshot): RiskFeatures {
  const vulnerabilities = snapshot.vulnerabilities; const threatFindings = snapshot.threatFindings ?? [];
  const ranks: Record<RiskLevel, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const maximumVulnerabilitySeverity = vulnerabilities?.reduce<RiskLevel | undefined>((maximum, vulnerability) => !maximum || ranks[vulnerability.severity] > ranks[maximum] ? vulnerability.severity : maximum, undefined);
  const countsBySeverity = { low: 0, medium: 0, high: 0, critical: 0 } as Record<Exclude<RiskLevel, "unknown">, number>;
  for (const finding of threatFindings) countsBySeverity[finding.severity] += 1;
  let expected = 0; let completed = 0;
  switch (snapshot.subject.type) {
    case "package": { const checks = [vulnerabilities !== undefined, snapshot.exploitationChecked === true]; if (snapshot.packageSupplyChain) checks.push(true); if (snapshot.threatIntelChecked !== undefined) checks.push(snapshot.threatIntelChecked); expected = checks.length; completed = checks.filter(Boolean).length; break; }
    // omni-risk-v1 remains Scorecard-only for generic coverage and source error scoring.
    case "repository": expected = 1; completed = snapshot.scorecard === undefined ? 0 : 1; break;
    case "x402_endpoint": { const checks = [snapshot.endpoint?.listedOnCircle !== undefined, snapshot.activeProbeChecked === true, snapshot.historyChecked === true, snapshot.threatIntelChecked === true]; expected = checks.length; completed = checks.filter(Boolean).length; break; }
    case "dependency_set": expected = 1; completed = snapshot.evidence.length === 0 ? 0 : 1; break;
  }
  const repositoryEvidence = snapshot.repositoryEvidence; const history = snapshot.endpointHistory;
  const provenanceStates = { NOT_CHECKED: 0, UNAVAILABLE: 0, PRESENT_UNVERIFIED: 0, VERIFIED: 0, VERIFIED_SOURCE_MISMATCH: 0, VERIFIED_COMMIT_MISMATCH: 0, ERROR: 0 } as Record<ProvenanceState, number>;
  for (const observation of repositoryEvidence?.provenance ?? []) provenanceStates[observation.state] += 1;
  const count = (finding: string) => repositoryEvidence?.securityFiles.reduce((total, file) => total + file.findings.filter(item => item === finding).length, 0) ?? 0;
  return {
    schemaVersion: RISK_FEATURE_SCHEMA_VERSION, subject: snapshot.subject, vulnerabilities, vulnerabilityCount: vulnerabilities?.length ?? 0, knownExploitedVulnerabilityCount: vulnerabilities?.filter(item => item.knownExploited).length ?? 0, maximumVulnerabilitySeverity, exploitationChecked: snapshot.exploitationChecked === true,
    package: { present: snapshot.packageSupplyChain !== undefined, deprecated: snapshot.packageSupplyChain?.deprecated ?? false, installLifecycleScript: snapshot.packageSupplyChain?.hasInstallScript ?? false, integrityPresent: snapshot.packageSupplyChain?.integrityPresent ?? false, maintainerCount: snapshot.packageSupplyChain?.maintainerCount },
    repository: { present: repositoryEvidence !== undefined, partial: repositoryEvidence?.coverage.status === "partial", installLifecycleScriptCount: count("INSTALL_LIFECYCLE_SCRIPT"), downloadExecutePatternCount: count("DOWNLOAD_EXECUTE_PATTERN"), mutableActionRefCount: count("MUTABLE_GITHUB_ACTION_REF"), workflowWritePermissionCount: count("WORKFLOW_WRITE_PERMISSION"), exactDependencyCount: repositoryEvidence?.dependencies.exact.length ?? 0, unresolvedDependencyCount: repositoryEvidence?.dependencies.unresolved.length ?? 0, provenanceStates },
    scorecard: snapshot.scorecard, threatIntel: { checked: snapshot.threatIntelChecked === true, findings: threatFindings, matchCount: threatFindings.length, countsBySeverity },
    endpoint: { present: snapshot.endpoint !== undefined, listedOnCircle: snapshot.endpoint?.listedOnCircle, supportsGateway: snapshot.endpoint?.supportsGateway, supportsVanilla: snapshot.endpoint?.supportsVanilla, responseStatus: snapshot.endpoint?.responseStatus },
    history: { checked: snapshot.historyChecked === true && history !== undefined, present: history !== undefined, payToChangeCount: history?.payToChangeCount ?? 0, networkChangeCount: history?.networkChangeCount ?? 0, priceChangeCount: history?.priceChangeCount ?? 0, schemaChangeCount: history?.schemaChangeCount ?? 0, providerChangeCount: history?.providerChangeCount ?? 0 },
    sourceErrorCount: snapshot.sourceErrors?.length ?? 0, coverage: { completed, expected }, evidenceCount: snapshot.evidence.length
  };
}
