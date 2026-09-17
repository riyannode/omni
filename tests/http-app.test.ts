import { afterEach, describe, expect, test } from "bun:test";
import type { AddressInfo } from "node:net";
import { parse } from "yaml";
import type { RequestHandler } from "express";
import { createApp } from "../src/http/app.ts";
import type { HistoryStore } from "../src/data/history.ts";
import type { ThreatIntelStore } from "../src/data/threat-intel.ts";
import type { OmniIntelligence } from "../src/services.ts";
import type { PaidRequestStore } from "../src/data/paid-requests.ts";
import { createPaidRequestStore } from "../src/data/paid-requests.ts";
import { CircleTransferLookup } from "../src/payments/circle-transfers.ts";

const servers: Array<ReturnType<ReturnType<typeof createApp>["listen"]>> = [];

function testHistory(): HistoryStore {
  return {
    async recordEndpoint() {},
    async endpointHistory() { return undefined; },
    async isAvailable() { return false; }
  };
}

function testThreatIntel(): ThreatIntelStore {
  return {
    async lookupEndpoint() { return { checked: false, findings: [] }; },
    async lookupPackage() { return { checked: false, findings: [] }; },
    async status() { return { available: false, configured: false, activeIndicators: 0, sources: 0 }; }
  };
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))));
});

describe("HTTP machine-readable documents", () => {
  test("serves /llms.txt with the configured runtime base URL as plain text", async () => {
    const passThrough: RequestHandler = (_req, _res, next) => next();
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => passThrough },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
      publicBaseUrl: "https://omni.example-real.com"
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", () => resolve());
      server.once("error", reject);
    });

    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("test server has no TCP address");
    const response = await fetch(`http://127.0.0.1:${(address as AddressInfo).port}/llms.txt`);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/plain");
    expect(body).toContain("https://omni.example-real.com/");
    expect(body).not.toContain("https://omni.example.com");
    const ready = await fetch(`http://127.0.0.1:${(address as AddressInfo).port}/ready`);
    expect(ready.status).toBe(503);
    expect(await ready.json()).toMatchObject({ status: "degraded", dependencies: { paidRequests: "unavailable" } });
  });

  test("serves mainnet discovery contracts without claiming live mainnet acceptance", async () => {
    const passThrough: RequestHandler = (_req, _res, next) => next();
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => passThrough },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
      publicBaseUrl: "https://api.askomni.xyz"
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const [llmsResponse, apiResponse] = await Promise.all([
      fetch(`${origin}/llms.txt`), fetch(`${origin}/openapi.yaml`)
    ]);
    expect(llmsResponse.status).toBe(200);
    expect(apiResponse.status).toBe(200);
    expect(llmsResponse.headers.get("content-type")).toContain("text/plain");
    expect(apiResponse.headers.get("content-type")).toContain("application/yaml");
    const llms = await llmsResponse.text();
    const yaml = await apiResponse.text();
    for (const document of [llms, yaml]) {
      expect(document).toContain("https://gateway-api.circle.com");
      expect(document).toContain("Arc Mainnet configuration: prepared / pending live acceptance");
      expect(document).toContain("Arc Testnet paid lifecycle: verified historically");
      expect(document).not.toMatch(/ARC-TESTNET|eip155:5042002|gateway-api-testnet|Arc Mainnet paid lifecycle verified/);
    }
    const generic = llms.split("## Mainnet payment guidance")[1]!.split("## TRY WITH YOUR AGENT")[0]!;
    expect(generic).toContain("any acceptable Circle-supported MAINNET option actually offered by PAYMENT-REQUIRED");
    expect(generic).toContain("No testnet use or fallback");
    expect(generic).not.toContain("eip155:5042");
    expect(generic).toContain("If no acceptable mainnet option exists");
    expect(generic).toContain("enough Gateway balance");
    expect(generic).toContain("same HTTPS origin, path, and query names/values");
    expect(generic).toContain("one fresh UUID v4 Idempotency-Key per logical request");
    expect(generic).toContain("Authorize at most one payment");
    expect(generic).toContain("Any allowed retry reuses the same request and key");
    expect(generic).toContain("If validation, funds, or payment state is uncertain: STOP");
    expect(generic).toContain("Never expose authentication, wallet, signing, or payment secrets");
    const envExample = await Bun.file(new URL("../.env.example", import.meta.url)).text();
    expect(envExample).toMatch(/^CIRCLE_FACILITATOR_URL=https:\/\/gateway-api\.circle\.com$/m);
    expect(envExample).not.toMatch(/^CIRCLE_FACILITATOR_URL=.*testnet/m);
    expect(llms).toContain("Circle CLI chain `ARC`");
    expect(llms).toContain("eip155:5042");
    expect(llms).toContain("unwrap data.response");
    expect(llms).toContain("Do not make another paid request or request another representation.");
    expect(llms).toContain("Report only facts present in OMNI JSON or directly observed during payment. Do not infer omitted details or map riskScore to a severity. OMNI dimension values are risk levels, not quality ratings.");
    expect(llms).not.toContain("https://omni.example.com");
    const api = parse(yaml);
    expect(api.servers).toEqual([{ url: "https://api.askomni.xyz" }]);
    expect(api.externalDocs.url).toBe("https://api.askomni.xyz/llms.txt");
    const routes = [
      ["/v1/package/risk", "get", "0.005000", "$0.005"],
      ["/v1/repo/risk", "get", "0.010000", "$0.01"],
      ["/v1/dependencies/risk", "post", "0.050000", "$0.05"],
      ["/v1/x402/endpoint/preflight", "get", "0.010000", "$0.01"]
    ] as const;
    expect(Object.keys(api.paths).sort()).toEqual(["/health", "/ready", ...routes.map(([path]) => path)].sort());
    for (const [path, method, amount, price] of routes) {
      expect(Object.keys(api.paths[path])).toEqual([method]);
      const operation = api.paths[path][method];
      expect(operation["x-payment-info"].price).toEqual({ mode: "fixed", currency: "USDC", amount });
      expect(operation["x-payment-info"].protocols).toEqual([{ x402: {} }]);
      expect(operation.parameters).toContainEqual({ $ref: "#/components/parameters/IdempotencyKey" });
      expect(operation.responses["200"].content["application/json"]).toBeDefined();
      expect(operation.responses["402"]).toEqual({ $ref: "#/components/responses/PaymentRequired" });
      expect(llms).toContain(`${method.toUpperCase()} ${path}`);
      expect(llms).toContain(`${price} USDC`);
    }
    expect(api.components.parameters.IdempotencyKey.description).toContain("Required when submitting PAYMENT-SIGNATURE");
    expect(api.components.parameters.IdempotencyKey.description).toContain("UUID v4");
    expect(api.components.responses.PaymentRequired.headers["PAYMENT-REQUIRED"].required).toBe(true);
    expect(api.components.schemas.RiskAssessmentResponse.description).toContain("Compact machine-readable JSON");
    expect(api.components.schemas.CompactRiskAssessmentFields.properties).not.toHaveProperty("artifact");
    expect(api.components.schemas.CompactRiskAssessmentFields.properties).not.toHaveProperty("evidence");
  });

  test("returns HTTP 200 when the paid request store is available", async () => {
    const availableStore = { isAvailable: async () => true } as PaidRequestStore;
    const passThrough: RequestHandler = (_req, _res, next) => next();
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => passThrough },
      paidRequests: availableStore,
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", () => resolve());
      server.once("error", reject);
    });
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("test server has no TCP address");
    const response = await fetch(`http://127.0.0.1:${(address as AddressInfo).port}/ready`);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ status: "ready", dependencies: { paidRequests: "available" } });
  });
});
