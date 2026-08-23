import { describe, expect, test } from "bun:test";
import { CachedLoader, type Cache } from "../src/data/cache.ts";
import { RiskEngine } from "../src/domain/risk-engine.ts";
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
});
