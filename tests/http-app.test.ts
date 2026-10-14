import { afterEach, describe, expect, test } from "bun:test";
import type { AddressInfo } from "node:net";
import { parse } from "yaml";
import type { NextFunction, RequestHandler } from "express";
import { createApp } from "../src/http/app.ts";
import type { HistoryStore } from "../src/data/history.ts";
import type { ThreatIntelStore } from "../src/data/threat-intel.ts";
import type { OmniIntelligence } from "../src/services.ts";
import type { PaidRequestStore } from "../src/data/paid-requests.ts";
import { createPaidRequestStore } from "../src/data/paid-requests.ts";
import { CircleTransferLookup } from "../src/payments/circle-transfers.ts";
import type { CircleDiscovery } from "../src/payments/circle.ts";

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
    for (const document of [llms]) {
      expect(document).toContain("https://gateway-api.circle.com");
      expect(document).not.toMatch(/ARC-TESTNET|eip155:5042002|gateway-api-testnet|Arc Mainnet paid lifecycle verified/);
    }
    expect(yaml).not.toMatch(/ARC-TESTNET|eip155:5042002|gateway-api-testnet|Arc Mainnet paid lifecycle verified/);
    expect(llms).toContain("Arc Mainnet paid lifecycle: verified on September 17, 2026 on the tested");
    expect(llms).toContain("Historical Arc Testnet paid lifecycle was verified earlier on the tested");
    expect(yaml).toContain("Machine-consumable pre-execution risk evidence for software supply chain and x402 services.");
    expect(yaml).toContain("Paid per request through Circle Gateway nanopayments, including Arc Mainnet.");
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
      ["/v1/x402/endpoint/preflight", "get", "0.010000", "$0.01"],
      ["/v1/agent/risk", "get", "0.050000", "$0.05"]
    ] as const;
    expect(Object.keys(api.paths).sort()).toEqual(["/.well-known/x402", "/health", "/ready", ...routes.map(([path]) => path)].sort());
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

  test("serves /openapi.json with application/json and same content as /openapi.yaml", async () => {
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => (_req: Request, _res: Response, next: NextFunction) => next() },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
      publicBaseUrl: "https://api.askomni.xyz"
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", () => resolve());
      server.once("error", reject);
    });
    const addr = server.address() as AddressInfo;
    const origin = "http://127.0.0.1:" + String(addr.port);

    const yamlRes = await fetch(origin + "/openapi.yaml");
    expect(yamlRes.status).toBe(200);
    expect(yamlRes.headers.get("content-type")).toContain("application/yaml");
    const yamlText = await yamlRes.text();

    const jsonRes = await fetch(origin + "/openapi.json");
    expect(jsonRes.status).toBe(200);
    expect(jsonRes.headers.get("content-type")).toContain("application/json");
    const jsonText = await jsonRes.text();

    const yamlDoc = parse(yamlText) as any;
    const jsonDoc = JSON.parse(jsonText) as any;

    expect(jsonDoc.openapi).toBe("3.1.0");
    expect(yamlDoc.openapi).toBe("3.1.0");
    expect(jsonDoc).toEqual(yamlDoc);

    expect(jsonDoc.servers[0].url).toBe("https://api.askomni.xyz");
    expect(yamlDoc.servers[0].url).toBe("https://api.askomni.xyz");

    for (const path of ["/v1/package/risk", "/v1/repo/risk", "/v1/dependencies/risk", "/v1/x402/endpoint/preflight"]) {
      const methods = jsonDoc.paths[path];
      for (const method of Object.keys(methods)) {
        const op = methods[method];
        expect(op["x-payment-info"].protocols).toEqual([{ x402: {} }]);
      }
    }
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

describe("API root response", () => {
  test("returns service status with docs and health links", async () => {
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => (_req: Request, _res: Response, next: NextFunction) => next() },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", () => resolve());
      server.once("error", reject);
    });
    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;

    const rootRes = await fetch(`${origin}/`);
    expect(rootRes.status).toBe(200);
    expect(rootRes.headers.get("content-type")).toContain("application/json");
    expect(await rootRes.json()).toEqual({
      service: "OMNI",
      status: "online",
      docs: "/openapi.json",
      health: "/health",
      x402: "/.well-known/x402"
    });

    const healthRes = await fetch(`${origin}/health`);
    expect(healthRes.status).toBe(200);
    expect(await healthRes.json()).toEqual({ service: "OMNI", status: "healthy" });

    const readyRes = await fetch(`${origin}/ready`);
    expect(readyRes.status).toBe(503);
    expect(await readyRes.json()).toMatchObject({ status: "degraded" });

    const openapiRes = await fetch(`${origin}/openapi.json`);
    expect(openapiRes.status).toBe(200);
  });
});

describe("x402 discovery manifest", () => {
  function mockDiscovery(networks: string[]): CircleDiscovery {
    return {
      async getNetworks() {
        return networks;
      }
    };
  }

  function failingDiscovery(): CircleDiscovery {
    return {
      async getNetworks() {
        throw new Error("circle_gateway_discovery_unavailable");
      }
    };
  }

  test("GET /.well-known/x402 returns discovery manifest with correct structure", async () => {
    const passThrough: RequestHandler = (_req, _res, next) => next();
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => passThrough },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
      publicBaseUrl: "https://api.askomni.xyz",
      circleDiscovery: mockDiscovery(["eip155:1", "eip155:8453", "eip155:5042"])
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });

    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;

    const res = await fetch(`${origin}/.well-known/x402`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    const body = await res.json();

    expect(body.x402Version).toBe(2);
    expect(body.service).toBe("OMNI");
    expect(body.openapi).toBe("https://api.askomni.xyz/openapi.json");
    expect(body.paymentTerms).toBe("live_402_authoritative");
    expect(body.networks).toEqual(["eip155:1", "eip155:5042", "eip155:8453"]);
    expect(body.resources).toHaveLength(5);
    expect(body.resources[0]).toEqual({
      method: "GET",
      resource: "https://api.askomni.xyz/v1/package/risk",
      price: { currency: "USDC", amount: "0.005000" }
    });
  });

  test("paid resources are derived from OpenAPI x-payment-info", async () => {
    const passThrough: RequestHandler = (_req, _res, next) => next();
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => passThrough },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
      publicBaseUrl: "https://api.askomni.xyz",
      circleDiscovery: mockDiscovery(["eip155:8453"])
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });

    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;

    const res = await fetch(`${origin}/.well-known/x402`);
    const body = await res.json();
    const expected = [
      { method: "GET", resource: "https://api.askomni.xyz/v1/package/risk", price: { currency: "USDC", amount: "0.005000" } },
      { method: "GET", resource: "https://api.askomni.xyz/v1/repo/risk", price: { currency: "USDC", amount: "0.010000" } },
      { method: "POST", resource: "https://api.askomni.xyz/v1/dependencies/risk", price: { currency: "USDC", amount: "0.050000" } },
      { method: "GET", resource: "https://api.askomni.xyz/v1/x402/endpoint/preflight", price: { currency: "USDC", amount: "0.010000" } },
      { method: "GET", resource: "https://api.askomni.xyz/v1/agent/risk", price: { currency: "USDC", amount: "0.050000" } }
    ];
    expect(body.resources).toEqual(expected);
  });

  test("networks are deduplicated and sorted deterministically", async () => {
    const passThrough: RequestHandler = (_req, _res, next) => next();
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => passThrough },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
      publicBaseUrl: "https://api.askomni.xyz",
      circleDiscovery: mockDiscovery(["eip155:8453", "eip155:1", "eip155:8453", "eip155:5042"])
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });

    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;

    const res = await fetch(`${origin}/.well-known/x402`);
    const body = await res.json();
    expect(body.networks).toEqual(["eip155:1", "eip155:5042", "eip155:8453"]);
  });

  test("testnet network from mocked provider is included (no silent fallback override)", async () => {
    const passThrough: RequestHandler = (_req, _res, next) => next();
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => passThrough },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
      publicBaseUrl: "https://api.askomni.xyz",
      circleDiscovery: mockDiscovery(["eip155:8453", "eip155:11155111"])
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });

    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;

    const res = await fetch(`${origin}/.well-known/x402`);
    const body = await res.json();
    expect(body.networks).toEqual(["eip155:11155111", "eip155:8453"]);
  });

  test("returns 503 when Gateway discovery fails and no cache exists", async () => {
    const passThrough: RequestHandler = (_req, _res, next) => next();
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => passThrough },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
      publicBaseUrl: "https://api.askomni.xyz",
      circleDiscovery: failingDiscovery()
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });

    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;

    const res = await fetch(`${origin}/.well-known/x402`);
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "gateway_discovery_unavailable" });
  });

  test("returns 503 when no circleDiscovery is configured", async () => {
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

    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;

    const res = await fetch(`${origin}/.well-known/x402`);
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "discovery_unavailable" });
  });

  test("API root advertises x402 discovery manifest", async () => {
    const passThrough: RequestHandler = (_req, _res, next) => next();
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => passThrough },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
      publicBaseUrl: "https://api.askomni.xyz",
      circleDiscovery: mockDiscovery(["eip155:8453"])
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });

    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;

    const res = await fetch(`${origin}/`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      service: "OMNI",
      status: "online",
      docs: "/openapi.json",
      health: "/health",
      x402: "/.well-known/x402"
    });
  });

  test("existing routes remain accessible after manifest addition", async () => {
    const passThrough: RequestHandler = (_req, _res, next) => next();
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => passThrough },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
      publicBaseUrl: "https://api.askomni.xyz",
      circleDiscovery: mockDiscovery(["eip155:8453"])
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });
    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;

    const [health, ready, yamlRes, jsonRes] = await Promise.all([
      fetch(`${origin}/health`),
      fetch(`${origin}/ready`),
      fetch(`${origin}/openapi.yaml`),
      fetch(`${origin}/openapi.json`)
    ]);

    expect(health.status).toBe(200);
    expect(ready.status).toBe(503);
    expect(yamlRes.status).toBe(200);
    expect(jsonRes.status).toBe(200);
  });

  test("GET /v1/agent/risk rejects unsupported chain with HTTP 400 before payment", async () => {
    let gatewayInvoked = false;
    let agentRiskInvoked = false;
    const passThrough: RequestHandler = (_req, _res, next) => { gatewayInvoked = true; next(); };
    const omniMock: OmniIntelligence = {
      async agentRisk() { agentRiskInvoked = true; throw new Error("should not be called"); },
    } as unknown as OmniIntelligence;
    const app = createApp({
      omni: omniMock,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => passThrough },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });
    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;

    const res = await fetch(`${origin}/v1/agent/risk?chain=eip155:99999&agentId=1`);
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("unsupported_chain");
    expect(gatewayInvoked).toBe(false);
    expect(agentRiskInvoked).toBe(false);
  });

  test("GET /v1/agent/risk rejects missing RPC configuration before gateway or reservation", async () => {
    const originalRpc = process.env.ERC8004_RPC_OVERRIDE_1;
    delete process.env.ERC8004_RPC_OVERRIDE_1;
    let gatewayInvoked = false;
    let agentRiskInvoked = false;
    let reserveInvoked = false;
    const paidRequests = {
      reserve: async () => { reserveInvoked = true; throw new Error("reserve should not be called"); },
      isAvailable: async () => true,
    } as unknown as PaidRequestStore;
    const omniMock: OmniIntelligence = {
      async agentRisk() { agentRiskInvoked = true; throw new Error("should not be called"); },
    } as unknown as OmniIntelligence;
    const app = createApp({
      omni: omniMock,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => { gatewayInvoked = true; throw new Error("gateway should not be called"); } },
      paidRequests,
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    try {
      await new Promise<void>((resolve, reject) => {
        server.once("listening", resolve);
        server.once("error", reject);
      });
      const address = server.address() as AddressInfo;
      const origin = `http://127.0.0.1:${address.port}`;
      const res = await fetch(`${origin}/v1/agent/risk?chain=eip155:1&agentId=1`, { headers: { Accept: "application/json", "Idempotency-Key": "11111111-1111-4111-8111-111111111111" } });
      expect(res.status).toBe(503);
      expect(await res.json()).toMatchObject({ error: "erc8004_rpc_unavailable" });
      expect(gatewayInvoked).toBe(false);
      expect(reserveInvoked).toBe(false);
      expect(agentRiskInvoked).toBe(false);
      process.env.ERC8004_RPC_OVERRIDE_1 = "http://rpc.fixture.invalid";
      const invalid = await fetch(`${origin}/v1/agent/risk?chain=eip155:1&agentId=1`, { headers: { Accept: "application/json", "Idempotency-Key": "22222222-2222-4222-8222-222222222222" } });
      expect(invalid.status).toBe(503);
      expect(gatewayInvoked).toBe(false);
      expect(reserveInvoked).toBe(false);
    } finally {
      if (originalRpc === undefined) delete process.env.ERC8004_RPC_OVERRIDE_1;
      else process.env.ERC8004_RPC_OVERRIDE_1 = originalRpc;
    }
  });

  test("GET /v1/agent/risk rejects invalid uint256 with HTTP 400 before payment", async () => {
    let gatewayInvoked = false;
    const passThrough: RequestHandler = (_req, _res, next) => { gatewayInvoked = true; next(); };
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => passThrough },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });
    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;

    // UINT256_MAX + 1
    const res = await fetch(`${origin}/v1/agent/risk?chain=eip155:1&agentId=115792089237316195423570985008687907853269984665640564039457584007913129639936`);
    expect(res.status).toBe(400);
    expect(gatewayInvoked).toBe(false);
  });

  test("GET /v1/agent/risk rejects obsolete targetUrl input with HTTP 400 before payment", async () => {
    let gatewayInvoked = false;
    const passThrough: RequestHandler = (_req, _res, next) => { gatewayInvoked = true; next(); };
    const app = createApp({
      omni: {} as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: { require: () => passThrough },
      paidRequests: createPaidRequestStore(),
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32,
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });
    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;

    const res = await fetch(`${origin}/v1/agent/risk?chain=eip155:1&agentId=1&targetUrl=https://example.com/api`);
    expect(res.status).toBe(400);
    expect(gatewayInvoked).toBe(false);
  });
});
