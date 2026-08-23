import { describe, expect, test } from "bun:test";
import { CachedLoader, type Cache } from "../src/data/cache.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
import { OmniIntelligence } from "../src/services.ts";
import { CircleDiscoveryProvider } from "../src/providers/circle-discovery.ts";

describe("evidence freshness", () => {
  test("preserves the original cache observation and expiry across cache hits", async () => {
    const values = new Map<string, string>();
    const cache: Cache = {
      async get(key) { return values.get(key) ?? null; },
      async set(key, value) { values.set(key, value); }
    };
    const loader = new CachedLoader(cache);
    let loads = 0;
    const first = await loader.getOrLoadWithMetadata("circle:test", 60, async () => { loads += 1; return { ok: true }; });
    const second = await loader.getOrLoadWithMetadata("circle:test", 60, async () => { loads += 1; return { ok: false }; });

    expect(loads).toBe(1);
    expect(second).toEqual(first);
  });

  test("uses the oldest relevant evidence deadline, not assessedAt plus a fixed window", () => {
    const assessment = new RiskEngine().assess({
      subject: { type: "x402_endpoint", id: "https://example.com/pay" },
      evidence: [
        { source: "Circle Discovery", kind: "marketplace_listing", observedAt: "2026-08-23T10:00:00.000Z", expiresAt: "2026-08-23T10:01:00.000Z", detail: {} },
        { source: "OMNI active probe", kind: "unpaid_x402_handshake", observedAt: "2026-08-23T10:00:40.000Z", detail: {} }
      ]
    });

    expect(assessment.assessedAt).not.toBe("2026-08-23T10:00:00.000Z");
    expect(assessment.freshness).toEqual({
      oldestEvidenceAt: "2026-08-23T10:00:00.000Z",
      newestEvidenceAt: "2026-08-23T10:00:40.000Z",
      expiresAt: "2026-08-23T10:01:00.000Z"
    });
  });

  test("does not fabricate freshness timestamps when evidence is empty", () => {
    const assessment = new RiskEngine().assess({
      subject: { type: "x402_endpoint", id: "https://example.com/pay" },
      evidence: []
    });

    expect(assessment.freshness).toEqual({ oldestEvidenceAt: null, newestEvidenceAt: null });
  });

  test("Circle evidence keeps the cache fetch time when the assessment is repeated", async () => {
    const cache = new CachedLoader({
      values: new Map<string, string>(),
      async get(key) { return this.values.get(key) ?? null; },
      async set(key, value) { this.values.set(key, value); }
    } as Cache & { values: Map<string, string> });
    let requests = 0;
    const provider = new CircleDiscoveryProvider(cache, {} as never, {
      async json() {
        requests += 1;
        return { items: [{ resource: "https://example.com/pay", accepts: [{ network: "eip155:1", amount: "100", payTo: "0xabc" }], metadata: { method: "GET" } }] };
      }
    } as never);

    const first = await provider.findExact("https://example.com/pay");
    const second = await provider.findExact("https://example.com/pay");
    expect(requests).toBe(1);
    expect(second.evidence.observedAt).toBe(first.evidence.observedAt);
    expect(second.evidence.expiresAt).toBe(first.evidence.expiresAt);
  });

  test("records the current Circle observation before reading endpoint history", async () => {
    const order: string[] = [];
    const observation = { resource: "https://example.com/pay", payTo: "0xabc", network: "eip155:1", priceAtomic: "100", method: "POST", schemaHash: "schema", providerName: "provider" };
    const history = {
      async recordEndpoint(value: typeof observation) { expect(value).toEqual(observation); order.push("record"); },
      async endpointHistory() { order.push("read"); return { observationCount: 2, payToChangeCount: 1, priceChangeCount: 0, networkChangeCount: 0, schemaChangeCount: 0, providerChangeCount: 0, relatedResourcesByPayTo: 0 }; },
      async isAvailable() { return true; }
    };
    const omni = new OmniIntelligence(
      new RiskEngine(), new CachedLoader({ async get() { return null; }, async set() {} }),
      {} as never, {} as never, {} as never, {} as never,
      { async findExact() { return { item: { resource: observation.resource, metadata: { method: "POST" } }, observation, evidence: { source: "Circle Discovery", kind: "marketplace_listing", observedAt: "2026-08-23T10:00:00.000Z", detail: {} } }; } } as never,
      {} as never, history, { async lookupEndpoint() { return { checked: false, findings: [] }; }, async lookupPackage() { return { checked: false, findings: [] }; }, async status() { return { available: false, configured: false, activeIndicators: 0, sources: 0 }; } },
    );

    const assessment = await omni.endpointPreflight(observation.resource);
    expect(order).toEqual(["record", "read"]);
    expect(assessment.signals.some(signal => signal.code === "PAYMENT_DESTINATION_CHANGED")).toBe(true);
  });

  test("keeps a current-observation write failure as a history source error", async () => {
    const history = {
      async recordEndpoint() { throw new Error("history unavailable"); },
      async endpointHistory() { return undefined; },
      async isAvailable() { return false; }
    };
    const omni = new OmniIntelligence(
      new RiskEngine(), new CachedLoader({ async get() { return null; }, async set() {} }),
      {} as never, {} as never, {} as never, {} as never,
      { async findExact() { return { item: { resource: "https://example.com/pay", metadata: { method: "POST" } }, observation: { resource: "https://example.com/pay" }, evidence: { source: "Circle Discovery", kind: "marketplace_listing", observedAt: "2026-08-23T10:00:00.000Z", detail: {} } }; } } as never,
      {} as never, history, { async lookupEndpoint() { return { checked: false, findings: [] }; }, async lookupPackage() { return { checked: false, findings: [] }; }, async status() { return { available: false, configured: false, activeIndicators: 0, sources: 0 }; } },
    );

    const assessment = await omni.endpointPreflight("https://example.com/pay");
    expect(assessment.sourceErrors).toContain("OMNI history: current Circle observation could not be recorded: history unavailable");
    expect(assessment.evidence.some(item => item.source === "Circle Discovery")).toBe(true);
  });
});
