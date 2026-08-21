import type { RiskLevel, RiskSnapshot, ThreatFinding, VulnerabilityFinding } from "./risk.ts";

export const RISK_FEATURE_SCHEMA_VERSION = 1 as const;

export type RiskFeatures = {
  schemaVersion: typeof RISK_FEATURE_SCHEMA_VERSION;
  subject: RiskSnapshot["subject"];
  vulnerabilities: VulnerabilityFinding[] | undefined;
  vulnerabilityCount: number;
  knownExploitedVulnerabilityCount: number;
  maximumVulnerabilitySeverity: RiskLevel | undefined;
  exploitationChecked: boolean;
  package: {
    present: boolean;
    deprecated: boolean;
    installLifecycleScript: boolean;
    integrityPresent: boolean;
    maintainerCount: number | undefined;
  };
  scorecard: number | undefined;
  threatIntel: {
    checked: boolean;
    findings: ThreatFinding[];
    matchCount: number;
    countsBySeverity: Record<Exclude<RiskLevel, "unknown">, number>;
  };
  endpoint: {
    present: boolean;
    listedOnCircle: boolean | undefined;
    supportsGateway: boolean | undefined;
    supportsVanilla: boolean | undefined;
    responseStatus: number | undefined;
  };
  history: {
    checked: boolean;
    present: boolean;
    payToChangeCount: number;
    networkChangeCount: number;
    priceChangeCount: number;
    schemaChangeCount: number;
    providerChangeCount: number;
  };
  sourceErrorCount: number;
  coverage: { completed: number; expected: number };
  evidenceCount: number;
};

export function extractRiskFeatures(snapshot: RiskSnapshot): RiskFeatures {
  const vulnerabilities = snapshot.vulnerabilities;
  const threatFindings = snapshot.threatFindings ?? [];
  const severityRank: Record<RiskLevel, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const maximumVulnerabilitySeverity = vulnerabilities?.reduce<RiskLevel | undefined>((max, vuln) => {
    if (!max || severityRank[vuln.severity] > severityRank[max]) return vuln.severity;
    return max;
  }, undefined);
  const countsBySeverity = { low: 0, medium: 0, high: 0, critical: 0 } as Record<Exclude<RiskLevel, "unknown">, number>;
  for (const finding of threatFindings) countsBySeverity[finding.severity] += 1;

  let expected = 0;
  let completed = 0;
  switch (snapshot.subject.type) {
    case "package": {
      const checks = [vulnerabilities !== undefined, snapshot.exploitationChecked === true];
      if (snapshot.packageSupplyChain) checks.push(true);
      if (snapshot.threatIntelChecked !== undefined) checks.push(snapshot.threatIntelChecked);
      expected = checks.length; completed = checks.filter(Boolean).length; break;
    }
    case "repository": expected = 1; completed = snapshot.scorecard === undefined ? 0 : 1; break;
    case "x402_endpoint": {
      const checks = [snapshot.endpoint?.listedOnCircle !== undefined, snapshot.activeProbeChecked === true, snapshot.historyChecked === true, snapshot.threatIntelChecked === true];
      expected = checks.length; completed = checks.filter(Boolean).length; break;
    }
    case "dependency_set": expected = 1; completed = snapshot.evidence.length === 0 ? 0 : 1; break;
  }

  const history = snapshot.endpointHistory;
  return {
    schemaVersion: RISK_FEATURE_SCHEMA_VERSION,
    subject: snapshot.subject,
    vulnerabilities,
    vulnerabilityCount: vulnerabilities?.length ?? 0,
    knownExploitedVulnerabilityCount: vulnerabilities?.filter(v => v.knownExploited).length ?? 0,
    maximumVulnerabilitySeverity,
    exploitationChecked: snapshot.exploitationChecked === true,
    package: {
      present: snapshot.packageSupplyChain !== undefined,
      deprecated: snapshot.packageSupplyChain?.deprecated ?? false,
      installLifecycleScript: snapshot.packageSupplyChain?.hasInstallScript ?? false,
      integrityPresent: snapshot.packageSupplyChain?.integrityPresent ?? false,
      maintainerCount: snapshot.packageSupplyChain?.maintainerCount
    },
    scorecard: snapshot.scorecard,
    threatIntel: { checked: snapshot.threatIntelChecked === true, findings: threatFindings, matchCount: threatFindings.length, countsBySeverity },
    endpoint: {
      present: snapshot.endpoint !== undefined,
      listedOnCircle: snapshot.endpoint?.listedOnCircle,
      supportsGateway: snapshot.endpoint?.supportsGateway,
      supportsVanilla: snapshot.endpoint?.supportsVanilla,
      responseStatus: snapshot.endpoint?.responseStatus
    },
    history: {
      checked: snapshot.historyChecked === true && history !== undefined,
      present: history !== undefined,
      payToChangeCount: history?.payToChangeCount ?? 0,
      networkChangeCount: history?.networkChangeCount ?? 0,
      priceChangeCount: history?.priceChangeCount ?? 0,
      schemaChangeCount: history?.schemaChangeCount ?? 0,
      providerChangeCount: history?.providerChangeCount ?? 0
    },
    sourceErrorCount: snapshot.sourceErrors?.length ?? 0,
    coverage: { completed, expected },
    evidenceCount: snapshot.evidence.length
  };
}
