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
import { extractServices, getChainConfig, getChainRpcUrl, NEW_FEEDBACK_TOPIC, FEEDBACK_REVOKED_TOPIC, Erc8004ExecutionRevertedError, readAgentIdentity, scanAgentReputation, parseAgentCard, fetchAgentCard, isPrivateIp, hostnameResolvesToPrivate, MAX_FEEDBACK_EVENTS } from "../src/providers/erc8004.ts";
import { encodeAbiParameters, keccak256, stringToHex } from "viem";
import { OmniIntelligence } from "../src/services.ts";
import { CachedLoader } from "../src/data/cache.ts";
import { NoopAssessmentJournal } from "../src/data/assessment-journal.ts";
import { EventEmitter } from "node:events";

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
      evidence: [{ source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { status: "REGISTERED", registered: true, chainId: 1 } }],
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
      evidence: [{ source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { status: "NOT_REGISTERED", registered: false } }],
    });
    const { recommendation, scoreStatus, riskScore } = engine.assess(snapshot);
    expect(scoreStatus).toBe("insufficient_evidence");
    expect(riskScore).toBe(0);
    expect(recommendation).toBe("manual_review");
    expect(recommendation).not.toBe("do_not_proceed");
  });

  test("agent risk signals actually alter riskScore (MAX aggregation)", () => {
    const snapshot = minimalAgentSnapshot({
      evidence: [
        { source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { status: "REGISTERED", registered: true } },
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
        { source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { status: "REGISTERED", registered: true } },
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
      evidence: [{ source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { status: "REGISTERED", registered: true } }],
    });
    const assessment = engine.assess(snapshot);
    // Agent assessments use the agent-specific policy version
    expect(assessment.policyVersion).toBe("omni-agent-risk-v1");
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
        { source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { status: "REGISTERED", registered: true } },
        { source: "ERC-8004 Agent Card", kind: "agent_card", observedAt: new Date().toISOString(), detail: { serviceCount: 3 } },
      ],
    }));
    expect(features.agent.registered).toBe(true);
    expect(features.agent.servicesObserved).toBe(true);
  });

  test("detects RPC error vs confirmed non-registration", () => {
    const features = extractRiskFeatures(minimalAgentSnapshot({
      evidence: [
        { source: "ERC-8004 IdentityRegistry", kind: "agent_identity", observedAt: new Date().toISOString(), detail: { status: "UNAVAILABLE", registered: false, error: "RPC timeout" } },
      ],
    }));
    expect(features.agent.identityStatus).toBe("UNAVAILABLE");
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

process.env.ERC8004_RPC_OVERRIDE_1 = "https://rpc.fixture.invalid";
const providerConfig = getChainConfig("eip155:1")!;
const ownerResult = `0x${"0".repeat(63)}1`;

function rpcFixture(result: unknown | Error) {
  return { rpcPost: async (_url: string, method: string) => {
    if (result instanceof Error) throw result;
    if (method === "eth_call") return result;
    return "0x0";
  } } as never;
}

describe("ERC-8004 identity status", () => {
  test("ownerOf success is REGISTERED", async () => {
    const result = await readAgentIdentity(providerConfig, 42n, rpcFixture(ownerResult));
    expect(result).toMatchObject({ status: "REGISTERED", registered: true, ownerAddress: "0x0000000000000000000000000000000000000001" });
  });

  test("confirmed nonexistent/revert is NOT_REGISTERED", async () => {
    const result = await readAgentIdentity(providerConfig, 42n, rpcFixture(new Erc8004ExecutionRevertedError("execution reverted: nonexistent token")));
    expect(result).toMatchObject({ status: "NOT_REGISTERED", registered: false, error: undefined });
  });

  test("RPC timeout, malformed JSON, and transport errors are UNAVAILABLE", async () => {
    for (const error of [new Error("RPC timeout"), new Error("invalid JSON response"), new Error("transport error")]) {
      const result = await readAgentIdentity(providerConfig, 42n, rpcFixture(error));
      expect(result.status).toBe("UNAVAILABLE");
      expect(result.registered).toBe(false);
      expect(result.error).toContain(error.message);
    }
  });

  test("malformed ownerOf data is UNAVAILABLE", async () => {
    const result = await readAgentIdentity(providerConfig, 42n, rpcFixture("0x1234"));
    expect(result.status).toBe("UNAVAILABLE");
    expect(result.registered).toBe(false);
  });
});

function validCard(overrides: Record<string, unknown> = {}) {
  return {
    type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
    services: [{ name: "x402", endpoint: "https://agent.example/api" }],
    x402Support: true,
    active: true,
    registrations: [{ agentRegistry: `eip155:1:${providerConfig.identityRegistry}`, agentId: 42 }],
    supportedTrust: ["reputation"],
    ...overrides,
  };
}

describe("ERC-8004 registration validation", () => {
  test("valid card requires a matching self-reference", () => {
    const parsed = parseAgentCard("data:", validCard(), { agentRegistry: `eip155:1:${providerConfig.identityRegistry}`, agentId: 42n });
    expect(parsed.status).toBe("SELF_REFERENCE_MATCH");
  });

  test("wrong chain, registry, agentId, no match, and inactive cards are rejected", () => {
    for (const registration of [
      { agentRegistry: `eip155:8453:${providerConfig.identityRegistry}`, agentId: 42 },
      { agentRegistry: "eip155:1:0x0000000000000000000000000000000000000001", agentId: 42 },
      { agentRegistry: `eip155:1:${providerConfig.identityRegistry}`, agentId: 43 },
    ]) {
      const parsed = parseAgentCard("data:", validCard({ registrations: [registration] }), { agentRegistry: `eip155:1:${providerConfig.identityRegistry}`, agentId: 42n });
      expect(parsed.status).toBe("SELF_REFERENCE_MISMATCH");
    }
    expect(parseAgentCard("data:", validCard({ active: false })).status).toBe("INVALID");
    expect(parseAgentCard("data:", validCard({ registrations: [{ agentRegistry: "bad", agentId: 42 }] })).status).toBe("INVALID");
  });

  test("malformed services, x402Support, and supportedTrust are INVALID", () => {
    expect(parseAgentCard("data:", validCard({ services: ["bad"] })).status).toBe("INVALID");
    expect(parseAgentCard("data:", validCard({ x402Support: "true" })).status).toBe("INVALID");
    expect(parseAgentCard("data:", validCard({ supportedTrust: [42] })).status).toBe("INVALID");
    expect(parseAgentCard("data:", "not-object").status).toBe("INVALID");
  });
});

function feedbackLog(index: bigint, value: bigint, valueDecimals: number, client = "0x00000000000000000000000000000000000000aa") {
  const data = encodeAbiParameters(
    [{ type: "uint64" }, { type: "int128" }, { type: "uint8" }, { type: "string" }, { type: "string" }, { type: "string" }, { type: "string" }, { type: "bytes32" }],
    [index, value, valueDecimals, "quality", "", "https://agent.example/api", "", `0x${"00".repeat(32)}`]
  );
  return { topics: [NEW_FEEDBACK_TOPIC, `0x${42n.toString(16).padStart(64, "0")}`, `0x${client.slice(2).padStart(64, "0")}`, keccak256(stringToHex("quality"))], data };
}

function revokedLog(index: bigint, client = "0x00000000000000000000000000000000000000aa") {
  return { topics: [FEEDBACK_REVOKED_TOPIC, `0x${42n.toString(16).padStart(64, "0")}`, `0x${client.slice(2).padStart(64, "0")}`, `0x${index.toString(16).padStart(64, "0")}`], data: "0x" };
}

describe("ERC-8004 reputation scan", () => {
  test("signed int128, decimal values, bigint feedbackIndex, and cross-chunk exact revocation", async () => {
    const network = { rpcPost: async (_url: string, method: string, params: unknown[]) => {
      if (method === "eth_blockNumber") return "0x2710";
      const filter = params[0] as { topics: string[]; fromBlock: string };
      const from = BigInt(filter.fromBlock);
      if (filter.topics[0] === NEW_FEEDBACK_TOPIC) return from === 0n ? [feedbackLog(1n, -1n, 0), feedbackLog(2n, -50n, 1), feedbackLog(9007199254740992n, 0n, 0)] : [feedbackLog(3n, 50n, 0)];
      return from === 5001n ? [revokedLog(1n), revokedLog(3n)] : [];
    } } as never;
    const scan = await scanAgentReputation(providerConfig, 42n, new Set(), 3, network);
    expect(scan.historyCoverage).toBe("complete");
    expect(scan.feedback).toHaveLength(4);
    expect(scan.feedback.find(item => item.feedbackIndex === 1n)?.revoked).toBe(true);
    expect(scan.feedback.find(item => item.feedbackIndex === 2n)?.revoked).toBe(false);
    expect(scan.feedback.find(item => item.feedbackIndex === 2n)?.value).toBe(-50n);
    expect(scan.feedback.find(item => item.feedbackIndex === 9007199254740992n)?.feedbackIndex).toBe(9007199254740992n);
    expect(scan.feedback.find(item => item.feedbackIndex === 3n)?.value).toBe(50n);
    expect(scan.feedback.find(item => item.feedbackIndex === 3n)?.revoked).toBe(true);
  });

  test("event cap surfaces truncation and partial coverage", async () => {
    const many = Array.from({ length: MAX_FEEDBACK_EVENTS + 1 }, (_, index) => feedbackLog(BigInt(index + 1), 0n, 0));
    const network = { rpcPost: async (_url: string, method: string) => method === "eth_blockNumber" ? "0x2710" : many } as never;
    const scan = await scanAgentReputation(providerConfig, 42n, null, 1, network);
    expect(scan.truncated).toBe(true);
    expect(scan.historyCoverage).toBe("partial");
    expect(scan.errors.join(" ")).toContain("feedback event limit reached");
  });
});

describe("ERC-8004 SSRF classification and registration fetch caps", () => {
  test("rejects IPv6 loopback, ULA, all fe80::/10, and mapped private addresses", () => {
    for (const ip of ["::1", "fc00::", "fd12::", "fe80::", "fe90::", "fea0::", "febf::", "::ffff:127.0.0.1", "0:0:0:0:0:ffff:192.168.1.1"]) expect(isPrivateIp(ip)).toBe(true);
    expect(isPrivateIp("2001:4860:4860::8888")).toBe(false);
    expect(isPrivateIp("::ffff:8.8.8.8")).toBe(false);
  });

  test("mixed DNS rejects if any result is private", async () => {
    const network = { resolve4: async () => ["93.184.216.34", "10.0.0.1"], resolve6: async () => [] } as never;
    await expect(hostnameResolvesToPrivate("mixed.example", network)).resolves.toBe(true);
  });

  test("data URI cap rejects decoded payloads over 256 KiB", async () => {
    const small = Buffer.from(JSON.stringify(validCard())).toString("base64");
    await expect(fetchAgentCard(`data:application/json;base64,${small}`, { agentRegistry: `eip155:1:${providerConfig.identityRegistry}`, agentId: 42n })).resolves.toMatchObject({ status: "SELF_REFERENCE_MATCH" });
    const oversizedData = Buffer.from("x".repeat(256 * 1024 + 1)).toString("base64");
    await expect(fetchAgentCard(`data:application/json;base64,${oversizedData}`)).resolves.toMatchObject({ status: "UNAVAILABLE" });
  });

  test("HTTPS body cap, private redirect, and redirect downgrade are rejected", async () => {
    const makeNetwork = (responses: Array<{ statusCode: number; body: Buffer; location?: string }>) => ({
      resolve4: async (host: string) => host === "private.example" ? ["10.0.0.1"] : ["93.184.216.34"],
      resolve6: async () => [],
      request: ((_: unknown, callback: (response: unknown) => void) => {
        const response = responses.shift()!;
        const req = new EventEmitter() as EventEmitter & { end: () => void; write: () => void; destroy: () => void };
        req.end = () => {
          process.nextTick(() => {
            const res = new EventEmitter() as EventEmitter & { statusCode: number; headers: Record<string, string>; resume: () => void };
            res.statusCode = response.statusCode;
            res.headers = response.location ? { location: response.location } : {};
            res.resume = () => undefined;
            callback(res as never);
            res.emit("data", response.body);
            res.emit("end");
          });
        };
        req.write = () => undefined;
        req.destroy = () => undefined;
        return req as never;
      }) as never,
    });
    const oversized = makeNetwork([{ statusCode: 200, body: Buffer.from("x".repeat(256 * 1024 + 1)) }]);
    await expect(fetchAgentCard("https://public.example/card", undefined, oversized as never)).resolves.toMatchObject({ status: "UNAVAILABLE" });
    const privateRedirect = makeNetwork([{ statusCode: 302, location: "https://private.example/card", body: Buffer.alloc(0) }]);
    await expect(fetchAgentCard("https://public.example/card", undefined, privateRedirect as never)).resolves.toMatchObject({ status: "UNAVAILABLE" });
    const downgrade = makeNetwork([{ statusCode: 302, location: "http://public.example/card", body: Buffer.alloc(0) }]);
    await expect(fetchAgentCard("https://public.example/card", undefined, downgrade as never)).resolves.toMatchObject({ status: "UNAVAILABLE" });
  });
});

function serviceForAgent(provider: unknown, policy: unknown = { trustedReviewers: new Set<string>(), recognizedTags: [] }) {
  const cache = new CachedLoader({ async get() { return null; }, async set() {} });
  return new OmniIntelligence(new RiskEngine(), cache, {} as never, {} as never, {} as never, {} as never, {} as never, {} as never, {} as never, {} as never, new NoopAssessmentJournal(), {} as never, {} as never, policy as never, provider as never);
}

function agentProvider(identity: Record<string, unknown>, feedback: unknown[] = [], card?: unknown, probe = { redirectsToPrivate: false }) {
  return {
    readAgentIdentity: async () => identity,
    scanAgentReputation: async () => ({ feedback, blocksScanned: 100n, historyCoverage: "complete", truncated: false, totalEventsObserved: feedback.length, errors: [] }),
    fetchAgentCard: async () => card ?? { status: "UNAVAILABLE", error: "not used" },
    probeTargetUrlRedirectsToPrivate: async () => probe,
  };
}

describe("OmniIntelligence agent service path", () => {
  test("confirmed NOT_REGISTERED is insufficient evidence and RPC UNAVAILABLE stays unknown", async () => {
    const notRegistered = await serviceForAgent(agentProvider({ chainId: 1, status: "NOT_REGISTERED", registered: false })).agentRisk("42", "eip155:1");
    expect({ riskScore: notRegistered.riskScore, scoreStatus: notRegistered.scoreStatus, recommendation: notRegistered.recommendation }).toEqual({ riskScore: 0, scoreStatus: "insufficient_evidence", recommendation: "manual_review" });

    const unavailable = await serviceForAgent(agentProvider({ chainId: 1, status: "UNAVAILABLE", registered: false, error: "RPC timeout" })).agentRisk("42", "eip155:1");
    expect(unavailable.agentRisk.dimensions.agentIdentity).toBe("unknown");
    expect(unavailable.scoreStatus).toBe("insufficient_evidence");
  });

  test("registered identity reaches normal measured evaluation", async () => {
    const assessment = await serviceForAgent(agentProvider({ chainId: 1, status: "REGISTERED", registered: true })).agentRisk("42", "eip155:1");
    expect(assessment.agentRisk.dimensions.agentIdentity).toBe("registered_verified");
    expect(assessment.scoreStatus).toBe("measured");
  });

  test("actual extracted target states score unadvertised and private redirects", async () => {
    const card = { status: "SELF_REFERENCE_MATCH", card: validCard(), selfReferenceMatch: true };
    const notAdvertised = await serviceForAgent(agentProvider({ chainId: 1, status: "REGISTERED", registered: true, registrationUri: "data:card" }, [], card)).agentRisk("42", "eip155:1", "https://other.example/api");
    expect(notAdvertised.agentRisk.targetUrlStatus).toBe("NOT_ADVERTISED");
    expect(notAdvertised.riskScore).toBeGreaterThan(0);

    const redirected = await serviceForAgent(agentProvider({ chainId: 1, status: "REGISTERED", registered: true, registrationUri: "data:card" }, [], card, { redirectsToPrivate: true })).agentRisk("42", "eip155:1", "https://agent.example/api");
    expect(redirected.agentRisk.targetUrlStatus).toBe("ADVERTISED_REDIRECT_TO_PRIVATE");
    expect(redirected.riskScore).toBe(100);
  });

  test("operator reputation direction, decimals, and trusted reviewer filtering are enforced", async () => {
    const trusted = "0x00000000000000000000000000000000000000aa";
    const feedback = [
      { clientAddress: trusted, feedbackIndex: 1n, value: 7n, valueDecimals: 1, tag1: "quality", tag2: "", endpoint: "", feedbackURI: "", feedbackHash: "0x", revoked: false },
      { clientAddress: "0x00000000000000000000000000000000000000bb", feedbackIndex: 2n, value: 0n, valueDecimals: 1, tag1: "quality", tag2: "", endpoint: "", feedbackURI: "", feedbackHash: "0x", revoked: false },
    ];
    const policy = { trustedReviewers: new Set([trusted]), recognizedTags: [{ tag: "quality", direction: "higher_is_better", threshold: "0.8", expectedDecimals: 1, riskWeight: 70 }] };
    const higher = await serviceForAgent(agentProvider({ chainId: 1, status: "REGISTERED", registered: true }, feedback), policy).agentRisk("42", "eip155:1");
    expect(higher.riskScore).toBe(70);
    expect(higher.agentRisk.reputationSummary?.totalFeedback).toBe(2);
    expect(higher.agentRisk.reputationSummary?.scoreEligibleFeedback).toBe(1);
    const untrustedOnly = await serviceForAgent(agentProvider({ chainId: 1, status: "REGISTERED", registered: true }, [feedback[1]!]), { trustedReviewers: new Set<string>(), recognizedTags: policy.recognizedTags }).agentRisk("42", "eip155:1");
    expect(untrustedOnly.agentRisk.dimensions.agentReputation).toBe("insufficient");
    expect(untrustedOnly.riskScore).toBe(0);

    const lowerPolicy = { trustedReviewers: new Set([trusted]), recognizedTags: [{ tag: "quality", direction: "lower_is_better", threshold: "0.8", expectedDecimals: 1, riskWeight: 70 }] };
    const lowerFeedback = [{ ...feedback[0]!, value: 9n }];
    const lower = await serviceForAgent(agentProvider({ chainId: 1, status: "REGISTERED", registered: true }, lowerFeedback), lowerPolicy).agentRisk("42", "eip155:1");
    expect(lower.riskScore).toBe(70);

    const higherSafe = await serviceForAgent(agentProvider({ chainId: 1, status: "REGISTERED", registered: true }, [{ ...feedback[0]!, value: 9n }]), policy).agentRisk("42", "eip155:1");
    expect(higherSafe.riskScore).toBe(0);
    const lowerSafe = await serviceForAgent(agentProvider({ chainId: 1, status: "REGISTERED", registered: true }, [feedback[0]!]), lowerPolicy).agentRisk("42", "eip155:1");
    expect(lowerSafe.riskScore).toBe(0);
    const negativePolicy = { trustedReviewers: new Set([trusted]), recognizedTags: [{ tag: "quality", direction: "higher_is_better", threshold: "0", expectedDecimals: 0, riskWeight: 70 }] };
    const negative = await serviceForAgent(agentProvider({ chainId: 1, status: "REGISTERED", registered: true }, [{ ...feedback[0]!, value: -1n, valueDecimals: 0 }]), negativePolicy).agentRisk("42", "eip155:1");
    expect(negative.riskScore).toBe(70);
  });
});
