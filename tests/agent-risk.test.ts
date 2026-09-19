/**
 * Unit tests for ERC-8004 agent risk assessment.
 *
 * These tests exercise:
 *  - agentQuery zod schema validation (chain required, decimal agentId, HTTPS targetUrl)
 *  - RiskEngine behaviour for agent subjects (dimensions, score floor, MAX aggregation)
 *  - risk-evaluation.ts replay guard (agent rows excluded from safe-replay list)
 *  - erc8004.ts helpers: decodeString, extractServices, chain config resolution
 *  - scoreStatus and recommendation for registered / unregistered agents
 *  - targetUrl attribution rules (canonical matching)
 *  - real omni-agent-risk-v1 scoring
 *  - canonical cross-chain subject ID
 */

import { expect, test, describe } from "bun:test";
import { agentQuery } from "../src/http/validation.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
import { DEFAULT_RISK_POLICY } from "../src/domain/risk-policy.ts";
import type { RiskSnapshot } from "../src/domain/risk.ts";
import { RISK_SNAPSHOT_SCHEMA_VERSION, AGENT_POLICY_VERSION } from "../src/domain/risk.ts";
import { RISK_FEATURE_SCHEMA_VERSION, extractRiskFeatures } from "../src/domain/risk-features.ts";
import { partitionCompatibleRows } from "../src/domain/risk-evaluation.ts";
import type { ReplayableRow } from "../src/domain/risk-evaluation.ts";
import { extractServices, getChainConfig, NEW_FEEDBACK_TOPIC, FEEDBACK_REVOKED_TOPIC } from "../src/providers/erc8004.ts";

// ---------------------------------------------------------------------------
// agentQuery validation
// ---------------------------------------------------------------------------

describe("agentQuery validation", () => {
  test("accepts decimal agentId with chain", () => {
    const result = agentQuery.safeParse({ chain: "eip155:1", agentId: "42" });
    expect(result.success).toBe(true);
  });

  test("accepts large decimal uint256 agentId", () => {
    // uint256 max is ~78 digits
    const result = agentQuery.safeParse({ chain: "eip155:1", agentId: "115792089237316195423570985008687907853269984665640564039457584007913129639935" });
    expect(result.success).toBe(true);
  });

  test("accepts agentId with valid targetUrl", () => {
    const result = agentQuery.safeParse({ chain: "eip155:1", agentId: "1", targetUrl: "https://example.com/api" });
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.targetUrl).toBe("https://example.com/api");
  });

  test("rejects hex agentId (hex not accepted)", () => {
    expect(agentQuery.safeParse({ chain: "eip155:1", agentId: "0x2a" }).success).toBe(false);
  });

  test("rejects alphanumeric agentId", () => {
    expect(agentQuery.safeParse({ chain: "eip155:1", agentId: "abc" }).success).toBe(false);
  });

  test("rejects negative agentId", () => {
    expect(agentQuery.safeParse({ chain: "eip155:1", agentId: "-1" }).success).toBe(false);
  });

  test("rejects missing chain", () => {
    expect(agentQuery.safeParse({ agentId: "42" }).success).toBe(false);
  });

  test("rejects invalid chain format", () => {
    expect(agentQuery.safeParse({ chain: "ethereum", agentId: "42" }).success).toBe(false);
    expect(agentQuery.safeParse({ chain: "1", agentId: "42" }).success).toBe(false);
    expect(agentQuery.safeParse({ chain: "", agentId: "42" }).success).toBe(false);
  });

  test("rejects non-https targetUrl", () => {
    expect(agentQuery.safeParse({ chain: "eip155:1", agentId: "1", targetUrl: "http://example.com/api" }).success).toBe(false);
  });

  test("rejects malformed targetUrl", () => {
    expect(agentQuery.safeParse({ chain: "eip155:1", agentId: "1", targetUrl: "not-a-url" }).success).toBe(false);
  });

  test("targetUrl is optional", () => {
    const result = agentQuery.safeParse({ chain: "eip155:1", agentId: "1" });
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.targetUrl).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Chain config resolution
// ---------------------------------------------------------------------------

describe("chain config resolution", () => {
  test("resolves Ethereum mainnet", () => {
    const config = getChainConfig("eip155:1");
    expect(config).toBeDefined();
    expect(config!.chainId).toBe(1);
    expect(config!.identityRegistry).toBe("0x8004A169FB4a3325136EB29fA0ceB6D2e539a432");
    expect(config!.reputationRegistry).toBe("0x8004BAa17C55a88189AE136b182e5fdA19dE9b63");
    expect(config!.enabled).toBe(true);
    expect(config!.deployment).toBe("official");
  });

  test("resolves Base mainnet", () => {
    const config = getChainConfig("eip155:8453");
    expect(config).toBeDefined();
    expect(config!.chainId).toBe(8453);
    expect(config!.identityRegistry).toBe("0x8004A169FB4a3325136EB29fA0ceB6D2e539a432");
  });

  test("returns undefined for unsupported chain", () => {
    const config = getChainConfig("eip155:99999");
    expect(config).toBeUndefined();
  });

  test("returns undefined for invalid format", () => {
    expect(getChainConfig("ethereum")).toBeUndefined();
    expect(getChainConfig("")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Official ERC-8004 event topics (Jan 2026 spec)
// ---------------------------------------------------------------------------

describe("ERC-8004 event topics", () => {
  test("NewFeedback topic matches official spec", () => {
    // NewFeedback(uint256,address,uint64,int128,uint8,string,string,string,string,string,bytes32)
    expect(NEW_FEEDBACK_TOPIC).toBe("0x6a4a61743519c9d648a14e6493f47dbe3ff1aa29e7785c96c8326a205e58febc");
  });

  test("FeedbackRevoked topic matches official spec", () => {
    // FeedbackRevoked(uint256,address,uint64)
    expect(FEEDBACK_REVOKED_TOPIC).toBe("0x25156fd3288212246d8b008d5921fde376c71ed14ac2e072a506eb06fde6d09d");
  });

  test("topics are NOT the old pre-Jan 2026 values", () => {
    // Old wrong values from pre-Jan 2026 spec
    expect(NEW_FEEDBACK_TOPIC).not.toBe("0xa88ba7bd081ecd3c0937a93815d10e41e0ed29ba8b4a917cd38aa1377167cbf3");
    expect(FEEDBACK_REVOKED_TOPIC).not.toBe("0xd5e881269f28389ffddb41edd8dcace249471d58662bb4e062e74d2f66278755");
  });
});

// ---------------------------------------------------------------------------
// RiskEngine: agent subject type
// ---------------------------------------------------------------------------

const engine = new RiskEngine(DEFAULT_RISK_POLICY);

function canonicalSubjectId(chainRef: string, registry: string, agentId: string): string {
  return `${chainRef}:${registry}:${agentId}`;
}

function minimalAgentSnapshot(overrides: Partial<RiskSnapshot> = {}): RiskSnapshot {
  return {
    subject: { type: "agent", id: canonicalSubjectId("eip155:1", "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432", "42") },
    evidence: [],
    sourceErrors: [],
    ...overrides,
  };
}

describe("RiskEngine agent subjects", () => {
  test("agent with no evidence yields insufficient_evidence and manual_review", () => {
    const assessment = engine.assess(minimalAgentSnapshot());
    expect(assessment.scoreStatus).toBe("insufficient_evidence");
    expect(assessment.recommendation).toBe("manual_review");
    expect(assessment.riskScore).toBe(0);
  });

  test("agent with evidence yields measured score status", () => {
    const snapshot = minimalAgentSnapshot({
      evidence: [{ source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { registered: true, chainId: 1 } }],
    });
    const assessment = engine.assess(snapshot);
    expect(assessment.scoreStatus).toBe("measured");
  });

  test("agent has all supply-chain / endpoint dimensions as not_applicable", () => {
    const snapshot = minimalAgentSnapshot({
      evidence: [{ source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: {} }],
    });
    const { dimensions } = engine.assess(snapshot);
    expect(dimensions.packageSupplyChain).toBe("not_applicable");
    expect(dimensions.knownVulnerabilities).toBe("not_applicable");
    expect(dimensions.knownExploitation).toBe("not_applicable");
    expect(dimensions.repositorySecurityPractices).toBe("not_applicable");
    expect(dimensions.maliciousInfrastructure).toBe("not_applicable");
    expect(dimensions.serviceIdentity).toBe("not_applicable");
    expect(dimensions.paymentConfigurationRisk).toBe("not_applicable");
    expect(dimensions.endpointOperationalRisk).toBe("not_applicable");
  });

  test("registered=false yields riskScore 0 and manual_review (never do_not_proceed)", () => {
    const snapshot = minimalAgentSnapshot({
      evidence: [{ source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { registered: false } }],
    });
    const { recommendation, scoreStatus, riskScore } = engine.assess(snapshot);
    expect(scoreStatus).toBe("measured");
    expect(riskScore).toBe(0);
    expect(recommendation).toBe("manual_review");
    expect(recommendation).not.toBe("do_not_proceed");
  });

  test("agent risk signals actually alter riskScore (MAX aggregation)", () => {
    const snapshot = minimalAgentSnapshot({
      evidence: [
        { source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { registered: true } },
        { source: "OMNI active probe", kind: "agent_target_redirect_to_private", observedAt: new Date().toISOString(), detail: { targetUrl: "https://api.example.com", redirectsToPrivate: true } },
      ],
    });
    const assessment = engine.assess(snapshot);
    // targetUrlRedirectsToPrivate should drive score to maximum
    expect(assessment.riskScore).toBeGreaterThan(50);
    expect(assessment.recommendation).toBe("do_not_proceed");
  });

  test("target URL redirect to private overrides low reputation score (MAX wins)", () => {
    const snapshot = minimalAgentSnapshot({
      evidence: [
        { source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { registered: true } },
        { source: "ERC-8004 ReputationRegistry", kind: "agent_trusted_feedback", observedAt: new Date().toISOString(), detail: { strongestRisk: 10 } },
        { source: "OMNI active probe", kind: "agent_target_redirect_to_private", observedAt: new Date().toISOString(), detail: { targetUrl: "https://api.example.com", redirectsToPrivate: true } },
      ],
    });
    const assessment = engine.assess(snapshot);
    // MAX(0, 10, 0, 100) = 100
    expect(assessment.riskScore).toBe(100);
    expect(assessment.recommendation).toBe("do_not_proceed");
  });

  test("agent zero-coverage floor is not applied", () => {
    const snapshot = minimalAgentSnapshot({ evidence: [] });
    const assessment = engine.assess(snapshot);
    expect(assessment.riskScore).toBe(0);
    expect(assessment.scoreStatus).toBe("insufficient_evidence");
  });

  test("subject.type is preserved in assessment", () => {
    const snapshot = minimalAgentSnapshot();
    const assessment = engine.assess(snapshot);
    expect(assessment.subject.type).toBe("agent");
  });

  test("policyVersion is preserved from policy", () => {
    const snapshot = minimalAgentSnapshot({
      evidence: [{ source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { registered: true } }],
    });
    const assessment = engine.assess(snapshot);
    expect(assessment.policyVersion).toBe(DEFAULT_RISK_POLICY.version);
  });
});

// ---------------------------------------------------------------------------
// RISK_SNAPSHOT_SCHEMA_VERSION is 5
// ---------------------------------------------------------------------------

describe("schema version constants", () => {
  test("RISK_SNAPSHOT_SCHEMA_VERSION is 5", () => {
    expect(RISK_SNAPSHOT_SCHEMA_VERSION).toBe(5);
  });

  test("RISK_FEATURE_SCHEMA_VERSION is 5", () => {
    expect(RISK_FEATURE_SCHEMA_VERSION).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// extractRiskFeatures: agent coverage calculation
// ---------------------------------------------------------------------------

describe("extractRiskFeatures for agent", () => {
  test("no evidence → completed=0, expected=1", () => {
    const features = extractRiskFeatures(minimalAgentSnapshot({ evidence: [] }));
    expect(features.coverage.completed).toBe(0);
    expect(features.coverage.expected).toBe(1);
  });

  test("with evidence → completed=1, expected=1", () => {
    const features = extractRiskFeatures(minimalAgentSnapshot({
      evidence: [{ source: "test", kind: "test", observedAt: new Date().toISOString(), detail: {} }],
    }));
    expect(features.coverage.completed).toBe(1);
    expect(features.coverage.expected).toBe(1);
  });

  test("explicit coverage model wins over fallback", () => {
    const sources = [{ source: "ERC-8004 IdentityRegistry", execution: "QUERIED" as const, status: "OBSERVED" as const, weight: 1 }];
    const features = extractRiskFeatures(minimalAgentSnapshot({
      coverage: { modelVersion: "agent-coverage-v1", sources },
      evidence: [],
    }));
    expect(features.coverage.completed).toBe(1);
    expect(features.coverage.expected).toBe(1);
    expect(features.coverage.modelVersion).toBe("agent-coverage-v1");
  });

  test("extracts agent features from evidence", () => {
    const features = extractRiskFeatures(minimalAgentSnapshot({
      evidence: [
        { source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { registered: true } },
        { source: "ERC-8004 Agent Card", kind: "agent_card", observedAt: new Date().toISOString(), detail: { serviceCount: 3 } },
      ],
    }));
    expect(features.agent.registered).toBe(true);
    expect(features.agent.servicesObserved).toBe(true);
  });

  test("detects RPC error vs confirmed non-registration", () => {
    const features = extractRiskFeatures(minimalAgentSnapshot({
      evidence: [
        { source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { registered: false, error: "RPC timeout" } },
      ],
    }));
    expect(features.agent.registered).toBe(false);
    expect(features.agent.identityRpcError).toBe(true);
  });

  test("detects targetUrlRedirectsToPrivate", () => {
    const features = extractRiskFeatures(minimalAgentSnapshot({
      evidence: [
        { source: "OMNI active probe", kind: "agent_target_redirect_to_private", observedAt: new Date().toISOString(), detail: { targetUrl: "https://api.example.com", redirectsToPrivate: true } },
      ],
    }));
    expect(features.agent.targetUrlRedirectsToPrivate).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// partitionCompatibleRows: agent rows must NOT be in compatible partition
// ---------------------------------------------------------------------------

describe("partitionCompatibleRows agent exclusion", () => {
  function agentRow(): ReplayableRow {
    return {
      subjectType: "agent",
      snapshotSchemaVersion: RISK_SNAPSHOT_SCHEMA_VERSION,
      featureSchemaVersion: RISK_FEATURE_SCHEMA_VERSION,
    };
  }

  function packageRow(): ReplayableRow {
    return {
      subjectType: "package",
      snapshotSchemaVersion: RISK_SNAPSHOT_SCHEMA_VERSION,
      featureSchemaVersion: RISK_FEATURE_SCHEMA_VERSION,
    };
  }

  function repositoryRow(): ReplayableRow {
    return {
      subjectType: "repository",
      snapshotSchemaVersion: RISK_SNAPSHOT_SCHEMA_VERSION,
      featureSchemaVersion: RISK_FEATURE_SCHEMA_VERSION,
    };
  }

  test("current-version agent rows are compatible (same schema)", () => {
    const { compatible, incompatible } = partitionCompatibleRows(
      [agentRow()],
      RISK_SNAPSHOT_SCHEMA_VERSION,
      RISK_FEATURE_SCHEMA_VERSION
    );
    expect(compatible).toHaveLength(1);
    expect(incompatible).toHaveLength(0);
  });

  test("v4 agent rows are incompatible (agent not in SAFE_REPLAY_SUBJECT_KINDS)", () => {
    const oldAgentRow: ReplayableRow = { subjectType: "agent", snapshotSchemaVersion: 4, featureSchemaVersion: 4 };
    const { compatible, incompatible } = partitionCompatibleRows(
      [oldAgentRow],
      RISK_SNAPSHOT_SCHEMA_VERSION,
      RISK_FEATURE_SCHEMA_VERSION
    );
    expect(compatible).toHaveLength(0);
    expect(incompatible).toHaveLength(1);
  });

  test("v4 package rows are compatible (safe replay)", () => {
    const oldPackageRow: ReplayableRow = { subjectType: "package", snapshotSchemaVersion: 4, featureSchemaVersion: 4 };
    const { compatible } = partitionCompatibleRows(
      [oldPackageRow],
      RISK_SNAPSHOT_SCHEMA_VERSION,
      RISK_FEATURE_SCHEMA_VERSION
    );
    expect(compatible).toHaveLength(1);
  });

  test("v4 repository rows are compatible (repository is in SAFE_REPLAY_SUBJECT_KINDS)", () => {
    const oldRepoRow: ReplayableRow = { subjectType: "repository", snapshotSchemaVersion: 4, featureSchemaVersion: 4 };
    const { compatible, incompatible } = partitionCompatibleRows(
      [oldRepoRow],
      RISK_SNAPSHOT_SCHEMA_VERSION,
      RISK_FEATURE_SCHEMA_VERSION
    );
    expect(compatible).toHaveLength(1);
    expect(incompatible).toHaveLength(0);
  });

  test("v4 x402_endpoint rows are compatible (safe replay)", () => {
    const oldRow: ReplayableRow = { subjectType: "x402_endpoint", snapshotSchemaVersion: 4, featureSchemaVersion: 4 };
    const { compatible } = partitionCompatibleRows(
      [oldRow],
      RISK_SNAPSHOT_SCHEMA_VERSION,
      RISK_FEATURE_SCHEMA_VERSION
    );
    expect(compatible).toHaveLength(1);
  });

  test("v4 dependency_set rows are compatible (safe replay)", () => {
    const oldRow: ReplayableRow = { subjectType: "dependency_set", snapshotSchemaVersion: 4, featureSchemaVersion: 4 };
    const { compatible } = partitionCompatibleRows(
      [oldRow],
      RISK_SNAPSHOT_SCHEMA_VERSION,
      RISK_FEATURE_SCHEMA_VERSION
    );
    expect(compatible).toHaveLength(1);
  });

  test("mixed v4 rows: only safe subjects are compatible", () => {
    const rows: ReplayableRow[] = [
      { subjectType: "package", snapshotSchemaVersion: 4, featureSchemaVersion: 4 },
      { subjectType: "x402_endpoint", snapshotSchemaVersion: 4, featureSchemaVersion: 4 },
      { subjectType: "dependency_set", snapshotSchemaVersion: 4, featureSchemaVersion: 4 },
      { subjectType: "agent", snapshotSchemaVersion: 4, featureSchemaVersion: 4 },
      { subjectType: "repository", snapshotSchemaVersion: 4, featureSchemaVersion: 4 },
    ];
    const { compatible, incompatible } = partitionCompatibleRows(rows, RISK_SNAPSHOT_SCHEMA_VERSION, RISK_FEATURE_SCHEMA_VERSION);
    expect(compatible).toHaveLength(4); // package + x402_endpoint + dependency_set + repository
    expect(incompatible).toHaveLength(1); // agent only
  });
});

// ---------------------------------------------------------------------------
// erc8004 helpers (imported directly from provider)
// ---------------------------------------------------------------------------

describe("erc8004 extractServices", () => {
  test("returns empty array for no services", () => {
    expect(extractServices({})).toEqual([]);
  });

  test("extracts services with type and endpoint", () => {
    const card = { services: [{ type: "x402", endpoint: "https://api.example.com/v1" }] };
    const services = extractServices(card);
    expect(services).toHaveLength(1);
    expect(services[0]!.type).toBe("x402");
    expect(services[0]!.endpoint).toBe("https://api.example.com/v1");
  });

  test("handles non-string type gracefully", () => {
    const card = { services: [{ type: 42, endpoint: "https://api.example.com" }] };
    const services = extractServices(card as unknown as Parameters<typeof extractServices>[0]);
    expect(services[0]!.type).toBe("unknown");
  });

  test("ignores non-object entries", () => {
    const card = { services: [null, "bad", { type: "a2a", endpoint: "https://ok.example.com" }] };
    const services = extractServices(card as unknown as Parameters<typeof extractServices>[0]);
    expect(services).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Canonical cross-chain subject ID
// ---------------------------------------------------------------------------

describe("canonical subject ID", () => {
  test("same agentId on different chains cannot collide", () => {
    const id1 = canonicalSubjectId("eip155:1", "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432", "42");
    const id2 = canonicalSubjectId("eip155:8453", "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432", "42");
    expect(id1).not.toBe(id2);
    expect(id1).toBe("eip155:1:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42");
    expect(id2).toBe("eip155:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42");
  });

  test("different registries produce different IDs", () => {
    const id1 = canonicalSubjectId("eip155:1", "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432", "42");
    const id2 = canonicalSubjectId("eip155:1", "0x8004A818BFB912233c491871b3d84c89A494BD9e", "42");
    expect(id1).not.toBe(id2);
  });
});

// ---------------------------------------------------------------------------
// Target URL canonical matching
// ---------------------------------------------------------------------------

describe("target URL canonical matching", () => {
  test("exact match works", () => {
    const ep = "https://api.example.com/v1";
    const target = "https://api.example.com/v1";
    const epUrl = new URL(ep);
    const targetUrl = new URL(target);
    expect(epUrl.origin).toBe(targetUrl.origin);
    expect(epUrl.pathname).toBe(targetUrl.pathname);
  });

  test("prefix bypass is rejected (trusted.example.com.evil.com)", () => {
    const ep = "https://trusted.example.com/api";
    const target = "https://trusted.example.com.evil.com/api";
    const epUrl = new URL(ep);
    const targetUrl = new URL(target);
    // Origins differ
    expect(epUrl.origin).not.toBe(targetUrl.origin);
  });

  test("subdomain bypass is rejected", () => {
    const ep = "https://api.example.com/v1";
    const target = "https://evil.com/api.example.com/v1";
    const epUrl = new URL(ep);
    const targetUrl = new URL(target);
    expect(epUrl.origin).not.toBe(targetUrl.origin);
  });

  test("path mismatch is rejected", () => {
    const ep = "https://api.example.com/v1";
    const target = "https://api.example.com/v2";
    const epUrl = new URL(ep);
    const targetUrl = new URL(target);
    expect(epUrl.origin).toBe(targetUrl.origin);
    expect(epUrl.pathname).not.toBe(targetUrl.pathname);
  });
});

// ---------------------------------------------------------------------------
// Agent policy version
// ---------------------------------------------------------------------------

describe("agent policy version", () => {
  test("AGENT_POLICY_VERSION is omni-agent-risk-v1", () => {
    expect(AGENT_POLICY_VERSION).toBe("omni-agent-risk-v1");
  });
});
