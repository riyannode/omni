import { afterEach, describe, expect, test } from "bun:test";
import type { RequestHandler } from "express";
import { createApp } from "../src/http/app.ts";
import { createPaidRequestStore } from "../src/data/paid-requests.ts";
import { CircleTransferLookup } from "../src/payments/circle-transfers.ts";
import type { HistoryStore } from "../src/data/history.ts";
import type { ThreatIntelStore } from "../src/data/threat-intel.ts";
import type { OmniIntelligence } from "../src/services.ts";
import type { UrlRiskService } from "../src/services/url-risk.ts";
import type { GatewayWithHooks } from "../src/http/paid-route.ts";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

const servers: Server[] = [];
function history(): HistoryStore { return { async recordEndpoint() {}, async endpointHistory() { return undefined; }, async isAvailable() { return false; } }; }
function threatIntel(): ThreatIntelStore { return { async lookupEndpoint() { return { checked: false, findings: [] }; }, async lookupPackage() { return { checked: false, findings: [] }; }, async status() { return { available: false, configured: false, activeIndicators: 0, sources: 0 }; } }; }
function challengeGateway(prices: string[]): GatewayWithHooks {
  return {
    require(price: string): RequestHandler {
      prices.push(price);
      return (_req, res) => { res.setHeader("PAYMENT-REQUIRED", "challenge"); res.status(402).json({}); };
    }
  };
}
async function listen(app: ReturnType<typeof createApp>): Promise<string> {
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve, reject) => { server.once("listening", resolve); server.once("error", reject); });
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

afterEach(async () => { await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve())))); });

describe("GET /v1/url/risk", () => {
  test("returns an unpaid 402 challenge without reservation or assessment execution", async () => {
    const prices: string[] = [];
    let executions = 0;
    const store = createPaidRequestStore();
    const urlRisk = { async assess() { executions += 1; throw new Error("must not execute unpaid"); } } as unknown as UrlRiskService;
    const app = createApp({ omni: {} as OmniIntelligence, urlRisk, history: history(), threatIntel: threatIntel(), gateway: challengeGateway(prices), paidRequests: store, circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"), maxInFlight: 32 });
    const base = await listen(app);
    const response = await fetch(`${base}/v1/url/risk?url=${encodeURIComponent("https://example.com/")}`, { headers: { Accept: "application/json" } });
    expect(response.status).toBe(402);
    expect(response.headers.get("PAYMENT-REQUIRED")).toBe("challenge");
    expect(prices).toEqual(["$0.01"]);
    expect(executions).toBe(0);

    const freshKey = await fetch(`${base}/v1/url/risk?url=${encodeURIComponent("https://example.com/")}`, { headers: { Accept: "application/json", "Idempotency-Key": "11111111-1111-4111-8111-111111111111" } });
    expect(freshKey.status).toBe(402);
    expect(executions).toBe(0);
  });

  test("rejects invalid and policy-disallowed URL inputs before the payment gateway", async () => {
    const prices: string[] = [];
    const app = createApp({ omni: {} as OmniIntelligence, urlRisk: {} as UrlRiskService, history: history(), threatIntel: threatIntel(), gateway: challengeGateway(prices), paidRequests: createPaidRequestStore(), circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"), maxInFlight: 32 });
    const base = await listen(app);
    const values = [undefined, "not-a-url", "http://example.com/", "https://user:pass@example.com/", "https://127.0.0.1/", `https://example.com/${"x".repeat(2048)}`];
    for (const value of values) {
      const suffix = value === undefined ? "" : `?url=${encodeURIComponent(value)}`;
      const response = await fetch(`${base}/v1/url/risk${suffix}`);
      expect(response.status).toBe(400);
    }
    expect(prices).toEqual([]);
  });

  test("rejects a payment signature without a UUID v4 idempotency key", async () => {
    const prices: string[] = [];
    const app = createApp({ omni: {} as OmniIntelligence, urlRisk: {} as UrlRiskService, history: history(), threatIntel: threatIntel(), gateway: challengeGateway(prices), paidRequests: createPaidRequestStore(), circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"), maxInFlight: 32 });
    const base = await listen(app);
    const response = await fetch(`${base}/v1/url/risk?url=https%3A%2F%2Fexample.com%2F`, { headers: { "PAYMENT-SIGNATURE": "present" } });
    expect(response.status).toBe(400);
    expect(prices).toEqual([]);
  });
});
