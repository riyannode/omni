export const RISK_SNAPSHOT_SCHEMA_VERSION = 1 as const;

export type Recommendation = "proceed" | "proceed_with_caution" | "manual_review" | "do_not_proceed";
export type RiskLevel = "low" | "medium" | "high" | "critical" | "unknown";

export type Evidence = {
  source: string;
  kind: string;
  observedAt: string;
  detail: Record<string, unknown>;
  expiresAt?: string;
};

export type VulnerabilityFinding = {
  id: string;
  severity: RiskLevel;
  knownExploited: boolean;
  aliases: string[];
};

export type PackageSupplyChain = {
  registry: "npm";
  deprecated: boolean;
  hasInstallScript: boolean;
  integrityPresent: boolean;
  signatureCount: number;
  maintainerCount: number;
  publisher?: string;
  repositoryUrl?: string;
};

export type ThreatFinding = {
  indicatorType: "url" | "hostname" | "wallet" | "package";
  indicator: string;
  threatType: string;
  severity: Exclude<RiskLevel, "unknown">;
  source: string;
  reference?: string;
};

export type EndpointHistory = {
  observationCount: number;
  firstSeenAt?: string;
  lastSeenAt?: string;
  payToChangeCount: number;
  priceChangeCount: number;
  networkChangeCount: number;
  schemaChangeCount: number;
  providerChangeCount: number;
  relatedResourcesByPayTo: number;
};

export type RiskSignal = {
  code: string;
  severity: Exclude<RiskLevel, "unknown">;
  source: string;
  detail: Record<string, unknown>;
};

export type RiskSnapshot = {
  subject: { type: "package" | "repository" | "dependency_set" | "x402_endpoint"; id: string };
  vulnerabilities?: VulnerabilityFinding[];
  scorecard?: number;
  exploitationChecked?: boolean;
  packageSupplyChain?: PackageSupplyChain;
  threatIntelChecked?: boolean;
  threatFindings?: ThreatFinding[];
  endpointHistory?: EndpointHistory;
  historyChecked?: boolean;
  activeProbeChecked?: boolean;
  endpoint?: {
    listedOnCircle?: boolean;
    supportsGateway?: boolean;
    supportsVanilla?: boolean;
    responseStatus?: number;
    paymentOptions?: number;
    payTo?: string;
    network?: string;
    priceAtomic?: string;
  };
  evidence: Evidence[];
  sourceErrors?: string[];
};

export type RiskAssessment = {
  subject: RiskSnapshot["subject"];
  policyVersion: string;
  recommendation: Recommendation;
  riskScore: number;
  evidenceCoverage: number;
  dimensions: {
    knownVulnerabilities: RiskLevel;
    knownExploitation: RiskLevel;
    packageSupplyChain: RiskLevel;
    repositorySecurityPractices: RiskLevel;
    maliciousInfrastructure: RiskLevel;
    serviceIdentity: RiskLevel;
    paymentConfigurationRisk: RiskLevel;
    endpointOperationalRisk: RiskLevel;
  };
  signals: RiskSignal[];
  evidence: Evidence[];
  sourceErrors: string[];
  assessedAt: string;
  freshness: {
    oldestEvidenceAt: string | null;
    newestEvidenceAt: string | null;
    expiresAt?: string;
  };
};
