import { describe, expect, test } from "bun:test";
import { RiskEngine } from "../src/domain/risk-engine.ts";

const engine = new RiskEngine();

describe("RiskEngine", () => {
  test("returns do_not_proceed for known exploited critical evidence", () => {
    const result = engine.assess({
      subject: { type: "package", id: "npm:demo@1.0.0" },
      vulnerabilities: [{ id: "CVE-1", severity: "critical", knownExploited: true, aliases: [] }],
      exploitationChecked: true,
      evidence: [{ source: "test", kind: "vuln", observedAt: new Date().toISOString(), detail: {} }]
    });
    expect(result.recommendation).toBe("do_not_proceed");
    expect(result.riskScore).toBeGreaterThanOrEqual(75);
  });

  test("routes a high vulnerability to manual review", () => {
    const result = engine.assess({
      subject: { type: "package", id: "npm:demo@1.0.0" },
      vulnerabilities: [{ id: "GHSA-1", severity: "high", knownExploited: false, aliases: [] }],
      exploitationChecked: true,
      evidence: [{ source: "test", kind: "vuln", observedAt: new Date().toISOString(), detail: {} }]
    });
    expect(result.recommendation).toBe("manual_review");
    expect(result.dimensions.knownVulnerabilities).toBe("high");
  });

  test("requires manual review when no expected evidence is available", () => {
    const result = engine.assess({ subject: { type: "repository", id: "github.com/a/b" }, evidence: [], sourceErrors: ["source down"] });
    expect(result.evidenceCoverage).toBeLessThan(0.5);
    expect(result.recommendation).toBe("manual_review");
  });

  test("does not treat unknown vulnerability severity as low risk", () => {
    const result = engine.assess({
      subject: { type: "package", id: "npm:demo@1.0.0" },
      vulnerabilities: [{ id: "GHSA-unknown", severity: "unknown", knownExploited: false, aliases: [] }],
      exploitationChecked: true,
      evidence: [{ source: "test", kind: "vuln", observedAt: new Date().toISOString(), detail: {} }]
    });
    expect(result.recommendation).toBe("proceed_with_caution");
  });

  test("returns at least proceed_with_caution for an unlisted endpoint", () => {
    const result = engine.assess({
      subject: { type: "x402_endpoint", id: "https://example.com/paid" },
      endpoint: { listedOnCircle: false, responseStatus: 402, paymentOptions: 1 },
      evidence: [
        { source: "Circle Discovery", kind: "marketplace_listing", observedAt: new Date().toISOString(), detail: { listed: false } },
        { source: "OMNI active probe", kind: "http_probe", observedAt: new Date().toISOString(), detail: { status: 402 } }
      ]
    });
    expect(result.recommendation).toBe("proceed_with_caution");
  });

  test("reports full evidence coverage for a successful repository assessment", () => {
    const result = engine.assess({
      subject: { type: "repository", id: "github.com/a/b" },
      scorecard: 9.5,
      evidence: [{ source: "OpenSSF Scorecard", kind: "repository_security_practices", observedAt: new Date().toISOString(), detail: { score: 9.5 } }]
    });
    expect(result.evidenceCoverage).toBe(1);
  });

  test("does not return proceed when an endpoint evidence source fails", () => {
    const result = engine.assess({
      subject: { type: "x402_endpoint", id: "https://example.com/paid" },
      endpoint: { listedOnCircle: true },
      evidence: [{ source: "Circle Discovery", kind: "marketplace_listing", observedAt: new Date().toISOString(), detail: {} }],
      sourceErrors: ["Active probe: timeout"]
    });
    expect(result.evidenceCoverage).toBe(0.25);
    expect(result.recommendation).toBe("proceed_with_caution");
  });

  test("maps a 9.5/10 scorecard to low repository risk", () => {
    const result = engine.assess({
      subject: { type: "repository", id: "github.com/a/b" },
      scorecard: 9.5,
      evidence: [{ source: "OpenSSF Scorecard", kind: "repository_security_practices", observedAt: new Date().toISOString(), detail: { score: 9.5 } }]
    });
    expect(result.dimensions.repositorySecurityPractices).toBe("low");
  });
});

test("raises a critical threat-intelligence match to do_not_proceed", () => {
  const result = engine.assess({
    subject: { type: "x402_endpoint", id: "https://bad.example/pay" },
    endpoint: { listedOnCircle: true, responseStatus: 402 },
    activeProbeChecked: true,
    historyChecked: true,
    endpointHistory: { observationCount: 2, payToChangeCount: 0, priceChangeCount: 0, networkChangeCount: 0, schemaChangeCount: 0, providerChangeCount: 0, relatedResourcesByPayTo: 0 },
    threatIntelChecked: true,
    threatFindings: [{ indicatorType: "hostname", indicator: "bad.example", threatType: "malware", severity: "critical", source: "licensed-feed" }],
    evidence: []
  });
  expect(result.recommendation).toBe("do_not_proceed");
  expect(result.signals.some(signal => signal.code === "THREAT_INTELLIGENCE_MATCH")).toBe(true);
});

test("flags payout destination drift as a high-severity payment signal", () => {
  const result = engine.assess({
    subject: { type: "x402_endpoint", id: "https://api.example/pay" },
    endpoint: { listedOnCircle: true, responseStatus: 402 },
    activeProbeChecked: true,
    historyChecked: true,
    endpointHistory: { observationCount: 3, payToChangeCount: 1, priceChangeCount: 0, networkChangeCount: 0, schemaChangeCount: 0, providerChangeCount: 0, relatedResourcesByPayTo: 0 },
    threatIntelChecked: true,
    threatFindings: [],
    evidence: []
  });
  expect(result.recommendation).not.toBe("proceed");
  expect(result.signals.some(signal => signal.code === "PAYMENT_DESTINATION_CHANGED")).toBe(true);
});

test("treats install lifecycle scripts as evidence, not proof of malware", () => {
  const result = engine.assess({
    subject: { type: "package", id: "npm:demo@1.0.0" },
    vulnerabilities: [], exploitationChecked: true, threatIntelChecked: true, threatFindings: [],
    packageSupplyChain: { registry: "npm", deprecated: false, hasInstallScript: true, integrityPresent: true, signatureCount: 0, maintainerCount: 2 },
    evidence: []
  });
  expect(result.signals.some(signal => signal.code === "INSTALL_LIFECYCLE_SCRIPT_PRESENT")).toBe(true);
  expect(result.recommendation).not.toBe("do_not_proceed");
});

test("keeps unknown vulnerability severity unknown in the dimension", () => {
  const result = engine.assess({
    subject: { type: "package", id: "npm:demo@1.0.0" },
    vulnerabilities: [{ id: "GHSA-unknown", severity: "unknown", knownExploited: false, aliases: [] }],
    exploitationChecked: true,
    evidence: []
  });
  expect(result.dimensions.knownVulnerabilities).toBe("unknown");
});

test("unknown severity dominates a low vulnerability in the dimension", () => {
  const result = engine.assess({
    subject: { type: "package", id: "npm:demo@1.0.0" },
    vulnerabilities: [
      { id: "GHSA-low", severity: "low", knownExploited: false, aliases: [] },
      { id: "GHSA-unknown", severity: "unknown", knownExploited: false, aliases: [] }
    ],
    exploitationChecked: true,
    evidence: []
  });
  expect(result.dimensions.knownVulnerabilities).toBe("unknown");
});

test("does not turn partial no-signal package coverage into caution", () => {
  const result = engine.assess({
    subject: { type: "package", id: "npm:demo@1.0.0" },
    vulnerabilities: [],
    exploitationChecked: true,
    packageSupplyChain: { registry: "npm", deprecated: false, hasInstallScript: false, integrityPresent: true, signatureCount: 1, maintainerCount: 1 },
    threatIntelChecked: false,
    threatFindings: [],
    evidence: [],
    sourceErrors: ["Threat intelligence: unavailable"]
  });
  expect(result.riskScore).toBe(5);
  expect(result.recommendation).toBe("proceed");
});
