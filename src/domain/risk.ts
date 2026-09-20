export const RISK_SNAPSHOT_SCHEMA_VERSION = 5 as const;
export const MALICIOUS_PACKAGE_OBSERVATION_SCHEMA_VERSION = 1 as const;
export const PACKAGE_COVERAGE_MODEL_VERSION = "package-coverage-v2" as const;
export const REPOSITORY_COVERAGE_MODEL_VERSION = "repository-coverage-v1" as const;

export type Recommendation = "proceed" | "proceed_with_caution" | "manual_review" | "do_not_proceed";
export type RiskLevel = "low" | "medium" | "high" | "critical" | "unknown";
export type RiskDimensionLevel = RiskLevel | "not_applicable";
export type ScoreStatus = "measured" | "measured_partial" | "insufficient_evidence";
export type EvidenceExecution = "QUERIED" | "NOT_QUERIED";
export type EvidenceResolution = "OBSERVED" | "ABSENT" | "UNAVAILABLE" | "UNKNOWN" | "NOT_APPLICABLE";
export type EvidenceCoverageSource = { source: string; execution: EvidenceExecution; status: EvidenceResolution; weight: number };
export type EvidenceCoverage = { modelVersion: string; sources: EvidenceCoverageSource[] };
export type EvidenceCoverageSummary = { modelVersion: string; resolvedWeight: number; applicableWeight: number; sources: EvidenceCoverageSource[] };

export type Evidence = { source: string; kind: string; observedAt: string; detail: Record<string, unknown>; expiresAt?: string };
export type VulnerabilityFinding = { id: string; severity: RiskLevel; knownExploited: boolean; aliases: string[]; advisoryIds?: string[] };
export type OsvAdvisoryEvidence = {
  id: string;
  aliases: string[];
  raw: Record<string, unknown>;
  summary?: string;
  details?: string;
  sourceReference?: string;
  severity: RiskLevel;
  severitySource?: string;
  cvss: Array<{ type: string; score: string; source?: string }>;
  published?: string;
  modified?: string;
  withdrawn?: string | null;
  affected: OsvAffectedPackage[];
  references: Array<{ type: string; url: string }>;
  versionMatch: { ecosystem: string; name: string; version: string; matched: boolean; queryMatched: boolean; rationale: string };
};
export type PackageSupplyChain = { registry: "npm"; deprecated: boolean; hasInstallScript: boolean; integrityPresent: boolean; signatureCount: number; maintainerCount: number; publisher?: string; repositoryUrl?: string };
export type ThreatFinding = { indicatorType: "url" | "hostname" | "wallet" | "package"; indicator: string; threatType: string; severity: Exclude<RiskLevel, "unknown">; source: string; reference?: string };
export type OsvRangeEvent = { introduced?: string; fixed?: string; lastAffected?: string; limit?: string };
export type OsvAffectedRange = { type: string; repo?: string; events: OsvRangeEvent[] };
export type OsvCwe = { cweId?: string; name?: string; description?: string };
export type MaliciousPackageEvidenceFile = { path?: string; sha256?: string; tlsh?: string };
export type MaliciousPackageIntegrity = { filename?: string; hashes: Record<string, string> };
export type MaliciousPackageIndicators = { evidenceFiles: MaliciousPackageEvidenceFile[]; packageIntegrity: MaliciousPackageIntegrity[] };
export type OsvAffectedPackage = { package: { ecosystem: string; name: string; purl?: string }; versions: string[]; ranges: OsvAffectedRange[]; sourceReference?: string; cwes?: OsvCwe[]; indicators?: MaliciousPackageIndicators };
export type MaliciousPackageOrigin = { source: string; id?: string; modifiedAt?: string; importedAt?: string; sha256?: string; versions?: string[]; ranges?: OsvAffectedRange[] };
export type MaliciousPackageObservation = {
  schemaVersion: typeof MALICIOUS_PACKAGE_OBSERVATION_SCHEMA_VERSION;
  id: string;
  package: { ecosystem: string; name: string; purl?: string };
  queriedVersion: string;
  published?: string;
  modified?: string;
  sourceReference?: string;
  affected: OsvAffectedPackage[];
  origins: MaliciousPackageOrigin[];
};
export type EndpointHistory = { observationCount: number; firstSeenAt?: string; lastSeenAt?: string; payToChangeCount: number; priceChangeCount: number; networkChangeCount: number; schemaChangeCount: number; providerChangeCount: number; relatedResourcesByPayTo: number };
export type RiskSignal = { code: string; severity: Exclude<RiskLevel, "unknown">; source: string; detail: Record<string, unknown> };

export type RepositoryRiskSummary = {
  dependencies: { exact: number; unresolved: number; resolutionComplete: boolean };
  vulnerabilities: { total: number; unknown: number; low: number; medium: number; high: number; critical: number; highestSeverity: RiskLevel | null };
  knownExploitation: { kevMatches: number; status: RepositoryDependencyCisaKevObservation["status"] };
  maliciousPackages: { observed: number };
  threatIntelligence: { status: RepositoryThreatIntelStatus; findings: number; highestSeverity: Exclude<RiskLevel, "unknown"> | null };
  provenance: { sourceMismatch: number; commitMismatch: number; unavailable: number };
  securityPractices: { mutableActions: number; workflowWritePermissions: number; downloadExecuteFindings: number };
};

export type DependencyEcosystem = "NPM" | "CARGO" | "PYPI" | "GO";
export type ExactDependencyCoordinate = { ecosystem: DependencyEcosystem; name: string; version: string; sourcePath: string; manifestPath: string; workspacePath: string };
export type UnresolvedDependency = { ecosystem: DependencyEcosystem; name: string; requirement: string; sourcePath?: string; manifestPath: string; workspacePath: string };
export type RepositoryDependencyResolution = {
  manifestDiscoveryComplete: boolean;
  supportedManifestCount: number;
  unsupportedEcosystems: string[];
  resolversAttempted: string[];
  applicableExternalDependencyCount: number;
  unresolvedDependencyCount: number;
};
export type RepositorySecurityFile = { path: string; category: "manifest" | "workflow" | "build" | "release"; status: "inspected" | "missing" | "oversized" | "binary" | "unsupported"; findings: string[] };
export type ProvenanceState = "NOT_CHECKED" | "UNAVAILABLE" | "PRESENT_UNVERIFIED" | "VERIFIED" | "VERIFIED_SOURCE_MISMATCH" | "VERIFIED_COMMIT_MISMATCH" | "VERIFIED_COMMIT_UNCONFIRMED" | "ERROR";
export type ProvenanceObservation = { package: ExactDependencyCoordinate; state: ProvenanceState; source: "deps.dev"; sourceRepository?: string; sourceCommit?: string; expectedSourceMatches?: boolean; expectedCommitMatches?: boolean; attestationUrl?: string };
export type DependencyObservation = { coordinate: ExactDependencyCoordinate; licenses: string[]; advisoryIds: string[]; graph: { checked: boolean; nodeCount: number; error?: string }; provenance: ProvenanceObservation[] };
export type RepositoryThreatIntelStatus = "NOT_CHECKED" | "CHECKED" | "UNAVAILABLE" | "UNKNOWN";
export type RepositoryThreatIntelFinding = { coordinate: ExactDependencyCoordinate; finding: ThreatFinding };
export type RepositorySummaryStatus = "VALID" | "TRUNCATED" | "UNAVAILABLE" | "MISSING" | "INCONSISTENT" | "NOT_CHECKED" | "UNKNOWN";
export type RepositoryThreatIntelSummary = { status: RepositorySummaryStatus; findingsObserved: number; countsBySeverity: Record<Exclude<RiskLevel, "unknown">, number> };
export type RepositoryThreatIntelObservation = {
  status: RepositoryThreatIntelStatus;
  packagesInspected: ExactDependencyCoordinate[];
  findings: RepositoryThreatIntelFinding[];
  summary?: RepositoryThreatIntelSummary;
  errors: string[];
  limitations: string[];
};
export type RepositoryDependencyVulnerabilityStatus = "NOT_CHECKED" | "CHECKED" | "UNAVAILABLE" | "UNKNOWN";
export type RepositoryDependencyVulnerabilitySource = "OSV" | "CISA KEV";
export type RepositoryDependencyVulnerabilityFinding = {
  coordinate: ExactDependencyCoordinate;
  vulnerability: VulnerabilityFinding;
  sources: RepositoryDependencyVulnerabilitySource[];
};
export type RepositoryMaliciousPackageObservation = {
  coordinate: ExactDependencyCoordinate;
  id: string;
  source: "OSV";
};
export type RepositoryDependencyCisaKevObservation = {
  status: "NOT_QUERIED" | "CHECKED" | "UNAVAILABLE" | "UNKNOWN";
  correlatableCveIds: string[];
  matchedCveIds: string[];
};
export type RepositoryDependencyVulnerabilitySummary = { status: RepositorySummaryStatus; findingsObserved: number; countsBySeverity: Record<RiskLevel, number>; knownExploitedObserved: number; maliciousPackageObservationsObserved: number };
export type RepositoryDependencyVulnerabilityObservation = {
  status: RepositoryDependencyVulnerabilityStatus;
  packagesInspected: ExactDependencyCoordinate[];
  findings: RepositoryDependencyVulnerabilityFinding[];
  maliciousPackageObservations: RepositoryMaliciousPackageObservation[];
  summary?: RepositoryDependencyVulnerabilitySummary;
  cisaKev: RepositoryDependencyCisaKevObservation;
  errors: string[];
  limitations: string[];
};
export type RepositoryCollectionCoverage = { status: "complete" | "partial"; limitations: string[]; sourceErrors: string[] };
export type RepositoryEvidence = {
  target: { repository: string; requestedRef?: string; resolvedCommitSha?: string };
  githubCollection?: RepositoryCollectionCoverage;
  securityFiles: RepositorySecurityFile[];
  dependencies: { exact: ExactDependencyCoordinate[]; unresolved: UnresolvedDependency[]; resolvedGraph: { packagesChecked: number; nodesObserved: number; errors: string[] } };
  dependencyObservations: DependencyObservation[];
  dependencyVulnerabilities: RepositoryDependencyVulnerabilityObservation;
  dependencyThreatIntel: RepositoryThreatIntelObservation;
  dependencyResolution?: RepositoryDependencyResolution;
  coverage: { status: "complete" | "partial"; treeEntriesInspected: number; filesInspected: number; bytesInspected: number; limitations: string[] };
  sourceErrors: string[];
};

export type RiskSnapshot = {
  subject: { type: "package" | "repository" | "dependency_set" | "x402_endpoint" | "agent"; id: string };
  vulnerabilities?: VulnerabilityFinding[];
  scorecard?: number;
  exploitationChecked?: boolean;
  packageSupplyChain?: PackageSupplyChain;
  repositoryEvidence?: RepositoryEvidence;
  threatIntelChecked?: boolean;
  threatFindings?: ThreatFinding[];
  maliciousPackageObservations?: MaliciousPackageObservation[];
  endpointHistory?: EndpointHistory;
  historyChecked?: boolean;
  activeProbeChecked?: boolean;
  endpoint?: { listedOnCircle?: boolean; supportsGateway?: boolean; supportsVanilla?: boolean; responseStatus?: number; paymentOptions?: number; payTo?: string; network?: string; priceAtomic?: string };
  coverage?: EvidenceCoverage;
  evidence: Evidence[];
  sourceErrors?: string[];
};

export type RiskAssessment = {
  subject: RiskSnapshot["subject"]; policyVersion: string; scoreStatus: ScoreStatus; recommendation: Recommendation; riskScore: number; evidenceCoverage: number;
  coverage?: EvidenceCoverageSummary;
  dimensions: { knownVulnerabilities: RiskDimensionLevel; knownExploitation: RiskDimensionLevel; packageSupplyChain: RiskDimensionLevel; repositorySecurityPractices: RiskDimensionLevel; maliciousInfrastructure: RiskDimensionLevel; serviceIdentity: RiskDimensionLevel; paymentConfigurationRisk: RiskDimensionLevel; endpointOperationalRisk: RiskDimensionLevel };
  signals: RiskSignal[]; evidence: Evidence[]; sourceErrors: string[]; assessedAt: string;
  repositorySummary?: RepositoryRiskSummary;
  maliciousPackageObservations?: MaliciousPackageObservation[];
  freshness: { oldestEvidenceAt: string | null; newestEvidenceAt: string | null; expiresAt?: string };
};

// ---------------------------------------------------------------------------
// Agent-specific types (ERC-8004 subject extension, v5 schema)
// ---------------------------------------------------------------------------

export const AGENT_COVERAGE_MODEL_VERSION = "agent-coverage-v1" as const;
export const AGENT_POLICY_VERSION = "omni-agent-risk-v1" as const;
export const UINT256_MAX = 115792089237316195423570985008687907853269984665640564039457584007913129639935n;

/** Explicit identity status for unambiguous classification. */
export type AgentIdentityStatus = "REGISTERED" | "NOT_REGISTERED" | "UNAVAILABLE";
export type AgentIdentityRisk = "registered" | "unregistered" | "unknown";
export type AgentReputationRisk = "positive" | "neutral" | "negative" | "insufficient" | "unknown";

/**
 * Operator-configured recognized tag policy.
 * Each recognized tag defines how feedback values are interpreted.
 */
export type RecognizedTagPolicy = {
  /** Tag value from ERC-8004 tag1 */
  tag: string;
  /** Direction: higher value = better, or lower value = better */
  direction: "higher_is_better" | "lower_is_better";
  /** Threshold for determining if feedback indicates risk */
  threshold: string | number;
  /** Expected decimal places for valid feedback */
  expectedDecimals?: number;
  /** Allowed decimal places (if undefined, any 0-18 accepted) */
  allowedDecimals?: number[];
  /** Risk weight if threshold breached (0-100) */
  riskWeight: number;
};

/**
 * Agent reputation policy configuration.
 * Defines which reviewers are trusted and which tags are recognized.
 */
export type AgentReputationPolicy = {
  /** Trusted reviewer client addresses (lowercase) */
  trustedReviewers: Set<string>;
  /** Recognized tag policies */
  recognizedTags: RecognizedTagPolicy[];
};

export const DEFAULT_AGENT_REPUTATION_POLICY: AgentReputationPolicy = {
  trustedReviewers: new Set<string>(),
  recognizedTags: [],
};

/** Agent-specific risk dimensions, surfaced as a nested optional extension on RiskAssessment. */
export type AgentRiskDimensions = {
  /** Whether the agent is verifiably registered in the ERC-8004 IdentityRegistry on a production chain. */
  agentIdentity: "registered_verified" | "not_registered" | "unknown";
  /** Aggregated reputation signal derived from on-chain feedback, filtered to trusted reviewers when configured. */
  agentReputation: AgentReputationRisk;
  /** Service / x402 endpoint validity evidence from the agent card. */
  agentValidation: "services_observed" | "no_services" | "inactive_registration" | "card_unavailable" | "unknown";
};

/** Per-chain identity probe result surfaced inside agentRisk.chainEvidence. */
export type AgentChainIdentityResult = {
  chainId: number;
  registered: boolean;
  status: AgentIdentityStatus;
  ownerAddress: string | undefined;
  agentWallet: string | undefined;
  registrationUri: string | undefined;
  error: string | undefined;
};

/** Aggregated reputation summary derived from on-chain feedback. */
export type AgentReputationSummary = {
  chainId: number;
  totalFeedback: number;
  activeFeedback: number;
  revokedFeedback: number;
  /** Number of unique reviewers observed. */
  uniqueReviewers: number;
  /** Number of recognized tags (operator policy). */
  recognizedTags: number;
  /** Number of unrecognized tags. */
  unrecognizedTags: number;
  /** Number of feedback entries with valid expected decimals. */
  validDecimalsFeedback: number;
  /** Number of active feedback entries eligible for operator scoring. */
  scoreEligibleFeedback: number;
  /** Whether the scan covered the full block history (complete) or was bounded. */
  historyCoverage: "complete" | "partial";
  blocksScanned: string; // bigint serialized as decimal string
  errors: string[];
};

/** Service entry from the agent card, used for payload evidence. */
export type AgentServiceObservation = {
  type: string;
  endpoint?: string;
  schema?: string;
};

/** Optional agentRisk extension on RiskAssessment. Present only when subject.type === "agent". */
export type AgentRisk = {
  agentId: string;
  primaryChainId: number;
  agentWallet?: string;
  registrationUri?: string;
  agentName?: string;
  agentDescription?: string;
  dimensions: AgentRiskDimensions;
  chainEvidence: AgentChainIdentityResult[];
  reputationSummary?: AgentReputationSummary;
  services?: AgentServiceObservation[];
  /** ERC-8004 specific policy version for agent scoring. */
  policyVersion: string;
  /** Coverage model version for agent assessment. */
  coverageVersion: string;
};

export type AgentRiskAssessment = RiskAssessment & {
  agentRisk: AgentRisk;
};
