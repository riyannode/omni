import { afterEach, describe, expect, test } from "bun:test";
import type { RequestHandler } from "express";
import express from "express";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/http/app.ts";
import type { PaidRequest, PaidRequestStore, PaymentMetadata, PaidRequestReservation, ExecutionClaim } from "../src/data/paid-requests.ts";
import { CircleTransferLookup } from "../src/payments/circle-transfers.ts";
import type { GatewayWithHooks } from "../src/http/paid-route.ts";
import type { GatewayMiddleware } from "@circle-fin/x402-batching/server";
import type { HistoryStore } from "../src/data/history.ts";
import type { ThreatIntelStore } from "../src/data/threat-intel.ts";
import type { OmniIntelligence } from "../src/services.ts";
import { createHash, randomUUID } from "node:crypto";
import { createGatewayMiddleware } from "@circle-fin/x402-batching/server";
import { representationFromAccept } from "../src/http/result-representation.ts";
import { renderRiskMarkdown } from "../src/http/risk-markdown.ts";

const SELLER = "0x1111111111111111111111111111111111111111";
const PAYER = "0x2222222222222222222222222222222222222222";
const ASSET = "0x3333333333333333333333333333333333333333";
const NETWORK = "eip155:5042002";
const PACKAGE_INPUT = { ecosystem: "npm", name: "fixture", version: "1.0.0" };
const PACKAGE_KEY = "11111111-1111-4111-8111-111111111111";
const NONCE = `0x${"a".repeat(64)}`;

type BeforeSettleContext = Parameters<Parameters<GatewayMiddleware["onBeforeSettle"]>[0]>[0];
type AfterSettleContext = Parameters<Parameters<GatewayMiddleware["onAfterSettle"]>[0]>[0];
type SettleFailureContext = Parameters<Parameters<GatewayMiddleware["onSettleFailure"]>[0]>[0];
type VerifyFailureContext = Parameters<Parameters<GatewayMiddleware["onVerifyFailure"]>[0]>[0];

const servers: Server[] = [];

function clone<T>(value: T): T {
  return structuredClone(value);
}

function now(): string {
  return new Date().toISOString();
}

function requestFingerprint(route: string, method: string, input: unknown): string {
  return createHash("sha256").update(JSON.stringify({ route, method, input })).digest("hex");
}

function metadata(nonce = NONCE): PaymentMetadata {
  return { paymentNonce: nonce, payer: PAYER, network: NETWORK, payTo: SELLER, asset: ASSET, amountAtomic: "5000" };
}

function requestFor(state: PaidRequest["state"], overrides: Partial<PaidRequest> = {}): PaidRequest {
  return {
    idempotencyKey: PACKAGE_KEY,
    requestFingerprint: requestFingerprint("package", "GET", PACKAGE_INPUT),
    route: "package",
    state,
    paymentNonce: metadata().paymentNonce,
    payer: PAYER,
    network: NETWORK,
    payTo: SELLER,
    asset: ASSET,
    amountAtomic: "5000",
    finalStatus: 200,
    createdAt: now(),
    updatedAt: now(),
    ...overrides
  };
}

class MemoryPaidRequestStore implements PaidRequestStore {
  readonly rows = new Map<string, PaidRequest>();
  readonly failures = new Set<string>();
  readonly events: string[] = [];

  failNext(operation: string): void {
    this.failures.add(operation);
  }

  seed(request: PaidRequest): void {
    this.rows.set(request.idempotencyKey, clone(request));
  }

  private maybeFail(operation: string): void {
    if (this.failures.delete(operation)) throw new Error(`${operation} failed`);
  }

  async get(key: string): Promise<PaidRequest | undefined> {
    this.maybeFail("get");
    const request = this.rows.get(key);
    return request ? clone(request) : undefined;
  }

  async reserve(key: string, fingerprint: string, route: string): Promise<PaidRequestReservation> {
    this.maybeFail("reserve");
    const existing = this.rows.get(key);
    if (existing) {
      return existing.requestFingerprint === fingerprint
        ? { kind: "existing", request: clone(existing) }
        : { kind: "conflict", request: clone(existing) };
    }
    const created = requestFor("waiting_payment", {
      idempotencyKey: key,
      requestFingerprint: fingerprint,
      route
    });
    delete created.paymentNonce;
    delete created.payer;
    delete created.network;
    delete created.payTo;
    delete created.asset;
    delete created.amountAtomic;
    this.rows.set(key, created);
    return { kind: "created", request: clone(created) };
  }

  async claimPaymentAttempt(key: string, fingerprint: string): Promise<boolean> {
    this.maybeFail("claimPaymentAttempt");
    const request = this.rows.get(key);
    if (!request || request.requestFingerprint !== fingerprint || request.state !== "waiting_payment") return false;
    request.state = "settling";
    request.updatedAt = now();
    return true;
  }

  async persistPaymentNonce(key: string, fingerprint: string, payment: PaymentMetadata): Promise<void> {
    this.maybeFail("persistPaymentNonce");
    const request = this.rows.get(key);
    if (!request || request.requestFingerprint !== fingerprint || request.state !== "settling") throw new Error("not settling");
    if (request.paymentNonce && request.paymentNonce !== payment.paymentNonce) throw new Error("nonce changed");
    Object.assign(request, payment, { updatedAt: now() });
    this.events.push("nonce_persisted");
  }

  async markPaid(key: string, fingerprint: string, transferId: string, payment: PaymentMetadata): Promise<void> {
    this.maybeFail("markPaid");
    const request = this.rows.get(key);
    if (!request || request.requestFingerprint !== fingerprint || !["settling", "recovery_pending"].includes(request.state)) throw new Error("not settling");
    Object.assign(request, payment, { state: "paid", circleTransferId: transferId, executionLeaseAt: undefined, updatedAt: now() });
    this.events.push("paid");
  }

  async markRecoveryPending(key: string, fingerprint: string): Promise<void> {
    this.maybeFail("markRecoveryPending");
    const request = this.rows.get(key);
    if (request && request.requestFingerprint === fingerprint && ["settling", "recovery_pending"].includes(request.state)) {
      request.state = "recovery_pending";
      request.updatedAt = now();
    }
  }

  async releasePaymentAttempt(key: string, fingerprint: string): Promise<boolean> {
    this.maybeFail("releasePaymentAttempt");
    const request = this.rows.get(key);
    if (request && request.requestFingerprint === fingerprint && ["settling", "recovery_pending"].includes(request.state) && request.paymentNonce === undefined) {
      request.state = "waiting_payment";
      request.updatedAt = now();
      return true;
    }
    return false;
  }

  async claimExecution(key: string, fingerprint: string, leaseMs: number): Promise<ExecutionClaim> {
    this.maybeFail("claimExecution");
    const request = this.rows.get(key);
    if (!request || request.requestFingerprint !== fingerprint) return "unavailable";
    if (request.state === "completed") return "completed";
    if (request.state === "paid" || (request.state === "running" && request.executionLeaseAt !== undefined && Date.parse(request.executionLeaseAt) < Date.now() - leaseMs)) {
      const leaseId = randomUUID();
      request.state = "running";
      request.executionLeaseAt = new Date().toISOString();
      request.executionLeaseId = leaseId;
      request.updatedAt = now();
      return { kind: "claimed", leaseId };
    }
    if (request.state === "running") return "busy";
    return "unavailable";
  }

  async releaseExecution(key: string, fingerprint: string, leaseId: string): Promise<void> {
    this.maybeFail("releaseExecution");
    const request = this.rows.get(key);
    if (request && request.requestFingerprint === fingerprint && request.state === "running" && request.executionLeaseId === leaseId) {
      request.state = "paid";
      delete request.executionLeaseAt;
      delete request.executionLeaseId;
      request.updatedAt = now();
    }
  }

  async renewExecution(key: string, fingerprint: string, leaseId: string): Promise<boolean> {
    this.maybeFail("renewExecution");
    const request = this.rows.get(key);
    if (!request || request.requestFingerprint !== fingerprint || request.state !== "running" || request.executionLeaseId !== leaseId) return false;
    request.executionLeaseAt = new Date().toISOString();
    request.updatedAt = now();
    return true;
  }

  async complete(key: string, fingerprint: string, leaseId: string, result: unknown, status: number): Promise<void> {
    this.maybeFail("complete");
    const request = this.rows.get(key);
    if (!request || request.requestFingerprint !== fingerprint || request.state !== "running" || request.executionLeaseId !== leaseId) throw new Error("not running");
    Object.assign(request, { state: "completed", finalResult: clone(result), finalStatus: status, updatedAt: now() });
    delete request.executionLeaseAt;
    delete request.executionLeaseId;
    this.events.push("completed");
  }

  async isAvailable(): Promise<boolean> { return true; }
}

class TestGateway {
  private readonly beforeHooks: Array<(context: BeforeSettleContext) => Promise<unknown>> = [];
  private readonly afterHooks: Array<(context: AfterSettleContext) => Promise<void>> = [];
  private readonly verifyFailureHooks: Array<(context: VerifyFailureContext) => Promise<unknown>> = [];
  settlementCount = 0;
  prices: string[] = [];
  verificationFailure = false;
  settlementResult: { success: boolean; errorReason?: string } = { success: true };

  onBeforeSettle(hook: (context: BeforeSettleContext) => Promise<unknown>): this { this.beforeHooks.push(hook); return this; }
  onAfterSettle(hook: (context: AfterSettleContext) => Promise<void>): this { this.afterHooks.push(hook); return this; }
  onSettleFailure(_hook: (context: SettleFailureContext) => Promise<unknown>): this { return this; }
  onVerifyFailure(hook: (context: VerifyFailureContext) => Promise<unknown>): this { this.verifyFailureHooks.push(hook); return this; }

  require(price: string): RequestHandler {
    this.prices.push(price);
    return async (req, res, next) => {
      const signature = req.headers["payment-signature"];
      if (signature === undefined) {
        res.status(402).json({});
        return;
      }
      const paymentPayload = JSON.parse(Buffer.from(String(signature), "base64").toString("utf8"));
      const amount = price === "$0.005" ? "5000" : price === "$0.05" ? "50000" : "10000";
      const requirements = { scheme: "exact", network: NETWORK, asset: ASSET, amount, payTo: SELLER, maxTimeoutSeconds: 604900, extra: {} };
      if (this.verificationFailure) {
        for (const hook of this.verifyFailureHooks) await hook({ paymentPayload, requirements, error: new Error("injected verification failure") });
        res.status(402).json({ error: "Payment verification failed" });
        return;
      }
      for (const hook of this.beforeHooks) {
        const directive = await hook({ paymentPayload, requirements });
        if (directive && typeof directive === "object" && "abort" in directive) {
          res.status(402).json({ error: (directive as unknown as { reason: string }).reason });
          return;
        }
      }
      this.settlementCount += 1;
      const result = { ...this.settlementResult, transaction: `transfer-${this.settlementCount}`, network: NETWORK, payer: PAYER };
      for (const hook of this.afterHooks) await hook({ paymentPayload, requirements, result });
      if (!result.success) {
        res.status(402).json({ error: result.errorReason ?? "payment_failed" });
        return;
      }
      res.setHeader("PAYMENT-RESPONSE", Buffer.from(JSON.stringify({ success: true, transaction: result.transaction, network: NETWORK, payer: PAYER })).toString("base64"));
      await next();
    };
  }

  asGateway(): GatewayWithHooks { return this as unknown as GatewayWithHooks; }
}

function paymentHeader(nonce = NONCE): string {
  return Buffer.from(JSON.stringify({
    x402Version: 2,
    accepted: { scheme: "exact", network: NETWORK, asset: ASSET, amount: "5000", payTo: SELLER, maxTimeoutSeconds: 604900, extra: {} },
    payload: { authorization: { from: PAYER, to: SELLER, value: "5000", validAfter: "0", validBefore: "9999999999", nonce }, signature: "0x" }
  })).toString("base64");
}

function testHistory(): HistoryStore {
  return { async recordEndpoint() {}, async endpointHistory() { return undefined; }, async isAvailable() { return true; } };
}

function testThreatIntel(): ThreatIntelStore {
  return {
    async lookupEndpoint() { return { checked: false, findings: [] }; },
    async lookupPackage() { return { checked: false, findings: [] }; },
    async status() { return { available: true, configured: false, activeIndicators: 0, sources: 0 }; }
  };
}

async function listen(app: ReturnType<typeof express>): Promise<{ server: Server; url: string }> {
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("listening", () => resolve());
    server.once("error", reject);
  });
  const address = server.address() as AddressInfo;
  return { server, url: `http://127.0.0.1:${address.port}` };
}

async function httpServer(handler: (request: Request) => Response | Promise<Response>): Promise<{ server: Server; url: string; requests: string[] }> {
  const requests: string[] = [];
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    requests.push(`${req.method} ${url.pathname}${url.search}`);
    const response = await handler(new Request(url, { method: req.method ?? "GET" }));
    res.statusCode = response.status;
    response.headers.forEach((value, key) => res.setHeader(key, value));
    res.end(await response.text());
  });
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => resolve());
    server.once("error", reject);
  });
  const address = server.address() as AddressInfo;
  return { server, url: `http://127.0.0.1:${address.port}`, requests };
}

function createFixture(store: PaidRequestStore, gateway: TestGateway, omni: { calls: number; throwNext: boolean; packageRisk: (ecosystem: string, name: string, version: string) => Promise<unknown> }, circleUrl = "http://127.0.0.1:1") {
  return createApp({
    omni: omni as unknown as OmniIntelligence,
    history: testHistory(),
    threatIntel: testThreatIntel(),
    gateway: gateway.asGateway(),
    paidRequests: store,
    circleTransfers: new CircleTransferLookup(circleUrl, 500),
    maxInFlight: 32
  });
}

function createOmni() {
  const omni = {
    calls: 0,
    throwNext: false,
    async packageRisk() {
      omni.calls += 1;
      if (omni.throwNext) {
        omni.throwNext = false;
        throw new Error("injected OMNI failure");
      }
      return { subject: { type: "package", id: "npm:fixture@1.0.0" }, riskScore: 3, recommendation: "proceed" };
    }
  };
  return omni;
}

async function packageRequest(url: string, key: string, options: { payment?: boolean; nonce?: string; version?: string; accept?: string } = {}): Promise<Response> {
  const headers: Record<string, string> = { "Idempotency-Key": key };
  if (options.payment !== false) headers["PAYMENT-SIGNATURE"] = paymentHeader(options.nonce);
  if (options.accept !== undefined) headers.Accept = options.accept;
  return fetch(`${url}/v1/package/risk?ecosystem=npm&name=fixture&version=${encodeURIComponent(options.version ?? "1.0.0")}`, { headers });
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))));
});

describe("paid request idempotency", () => {
  test("accepts a valid UUID v4 key without durably reserving an unpaid 402", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    const app = createFixture(store, gateway, createOmni());
    const { url } = await listen(app);
    const response = await packageRequest(url, PACKAGE_KEY, { payment: false });
    expect(response.status).toBe(402);
    expect(store.rows.size).toBe(0);
    expect(gateway.settlementCount).toBe(0);
  });

  test("applies the same unpaid negotiation contract to all four paid routes without changing prices", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    const app = createFixture(store, gateway, createOmni());
    const { url } = await listen(app);
    const responses = await Promise.all([
      fetch(`${url}/v1/package/risk?ecosystem=npm&name=fixture&version=1.0.0`, { headers: { "Idempotency-Key": "11111111-1111-4111-8111-111111111112" } }),
      fetch(`${url}/v1/repo/risk?owner=fixture&repo=repo`, { headers: { "Idempotency-Key": "11111111-1111-4111-8111-111111111113" } }),
      fetch(`${url}/v1/dependencies/risk`, { method: "POST", headers: { "content-type": "application/json", "Idempotency-Key": "11111111-1111-4111-8111-111111111114" }, body: JSON.stringify({ packages: [PACKAGE_INPUT] }) }),
      fetch(`${url}/v1/x402/endpoint/preflight?url=https%3A%2F%2Fexample.com`, { headers: { "Idempotency-Key": "11111111-1111-4111-8111-111111111115" } })
    ]);
    expect(responses.map(response => response.status)).toEqual([402, 402, 402, 402]);
    expect(gateway.prices).toEqual(["$0.005", "$0.01", "$0.05", "$0.01"]);
    expect(store.rows.size).toBe(0);
  });

  test("rejects missing and malformed/non-v4 keys before payment", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    const app = createFixture(store, gateway, createOmni());
    const { url } = await listen(app);
    const missing = await fetch(`${url}/v1/package/risk?ecosystem=npm&name=fixture&version=1.0.0`, { headers: { "PAYMENT-SIGNATURE": paymentHeader() } });
    const malformed = await packageRequest(url, "not-a-uuid");
    const nonV4 = await packageRequest(url, "11111111-1111-3111-8111-111111111111");
    expect(missing.status).toBe(400);
    expect(malformed.status).toBe(400);
    expect(nonV4.status).toBe(400);
    expect(gateway.settlementCount).toBe(0);
  });

  test("releases a pre-settlement claim after verification failure so a later valid retry can pay", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    gateway.verificationFailure = true;
    const app = createFixture(store, gateway, createOmni());
    const { url } = await listen(app);
    expect((await packageRequest(url, PACKAGE_KEY)).status).toBe(402);
    expect(store.rows.get(PACKAGE_KEY)?.state).toBe("waiting_payment");
    gateway.verificationFailure = false;
    expect((await packageRequest(url, PACKAGE_KEY)).status).toBe(200);
    expect(gateway.settlementCount).toBe(1);
  });

  test("prevents an expired worker from completing or releasing a newer execution lease", async () => {
    const store = new MemoryPaidRequestStore();
    store.seed(requestFor("paid"));
    const first = await store.claimExecution(PACKAGE_KEY, requestFingerprint("package", "GET", PACKAGE_INPUT), 30_000);
    if (typeof first !== "object") throw new Error("first lease missing");
    const request = store.rows.get(PACKAGE_KEY)!;
    request.executionLeaseAt = new Date(Date.now() - 60_000).toISOString();
    const second = await store.claimExecution(PACKAGE_KEY, request.requestFingerprint, 30_000);
    if (typeof second !== "object") throw new Error("second lease missing");
    expect(second.leaseId).not.toBe(first.leaseId);
    await expect(store.complete(PACKAGE_KEY, request.requestFingerprint, first.leaseId, { stale: true }, 200)).rejects.toThrow("not running");
    await store.releaseExecution(PACKAGE_KEY, request.requestFingerprint, first.leaseId);
    expect(store.rows.get(PACKAGE_KEY)?.state).toBe("running");
    await store.complete(PACKAGE_KEY, request.requestFingerprint, second.leaseId, { ok: true }, 200);
  });

  test("stale reconciliation cannot downgrade a request already marked paid", async () => {
    const store = new MemoryPaidRequestStore();
    store.seed(requestFor("settling"));
    await store.markPaid(PACKAGE_KEY, requestFingerprint("package", "GET", PACKAGE_INPUT), "transfer-paid", metadata());
    await store.markRecoveryPending(PACKAGE_KEY, requestFingerprint("package", "GET", PACKAGE_INPUT));
    expect(store.rows.get(PACKAGE_KEY)?.state).toBe("paid");
  });

  test("returns conflict for the same key with a different fingerprint and performs zero new payment", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    const app = createFixture(store, gateway, createOmni());
    const { url } = await listen(app);
    expect((await packageRequest(url, PACKAGE_KEY)).status).toBe(200);
    const conflict = await packageRequest(url, PACKAGE_KEY, { version: "2.0.0" });
    expect(conflict.status).toBe(409);
    expect(await conflict.json()).toEqual({ error: "idempotency_conflict", retryable: false });
    expect(gateway.settlementCount).toBe(1);
  });

  test("replays the completed JSON body without settlement or OMNI execution", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    const omni = createOmni();
    const app = createFixture(store, gateway, omni);
    const { url } = await listen(app);
    const first = await packageRequest(url, PACKAGE_KEY);
    const firstBody = await first.json();
    const replay = await packageRequest(url, PACKAGE_KEY, { payment: false });
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual(firstBody);
    expect(omni.calls).toBe(1);
    expect(gateway.settlementCount).toBe(1);
    expect(replay.headers.get("PAYMENT-RESPONSE")).toBeNull();
  });

  test("negotiates JSON representations while preserving the default response", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    const app = createFixture(store, gateway, createOmni());
    const { url } = await listen(app);

    const noAccept = await packageRequest(url, "11111111-1111-4111-8111-111111111117");
    const explicitJson = await packageRequest(url, "11111111-1111-4111-8111-111111111118", { accept: "application/json" });
    const wildcard = await packageRequest(url, "11111111-1111-4111-8111-111111111119", { accept: "*/*" });
    const markdownQuality = await packageRequest(url, "11111111-1111-4111-8111-111111111120", { accept: "text/markdown;q=0.9, application/json;q=0.5" });
    const jsonQuality = await packageRequest(url, "11111111-1111-4111-8111-111111111121", { accept: "text/markdown;q=0.5, application/json;q=0.9" });

    expect(noAccept.headers.get("content-type")).toContain("application/json");
    expect(explicitJson.headers.get("content-type")).toContain("application/json");
    expect(wildcard.headers.get("content-type")).toContain("application/json");
    expect(markdownQuality.headers.get("content-type")).toContain("text/markdown");
    expect(jsonQuality.headers.get("content-type")).toContain("application/json");
    expect(noAccept.headers.get("vary")).toContain("Accept");
    expect(await explicitJson.json()).toMatchObject({ subject: { type: "package" } });
    expect(await wildcard.json()).toMatchObject({ subject: { type: "package" } });
  });

  test("rejects unsupported or unacceptable Accept values before payment", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    const app = createFixture(store, gateway, createOmni());
    const { url } = await listen(app);

    const unsupported = await packageRequest(url, "11111111-1111-4111-8111-111111111122", { payment: false, accept: "text/html" });
    const zeroQuality = await packageRequest(url, "11111111-1111-4111-8111-111111111123", { payment: false, accept: "application/json;q=0" });

    expect(unsupported.status).toBe(406);
    expect(zeroQuality.status).toBe(406);
    expect(await unsupported.json()).toEqual({ error: "not_acceptable", retryable: false });
    expect(await zeroQuality.json()).toEqual({ error: "not_acceptable", retryable: false });
    expect(gateway.settlementCount).toBe(0);
    expect(store.rows.size).toBe(0);
  });

  test("uses representation mapping and delimiter-safe Markdown code spans", async () => {
    expect(representationFromAccept("markdown")).toBe("markdown");
    expect(representationFromAccept("json")).toBe("json");
    expect(representationFromAccept(false)).toBeUndefined();

    const maliciousValue = "pkg`<script>alert(1)</script>```";
    const markdown = renderRiskMarkdown({
      subject: { type: "package", id: maliciousValue },
      recommendation: "proceed",
      riskScore: 1,
      signals: [],
      sourceErrors: []
    });
    const fence = "`".repeat(4);
    expect(markdown).toContain(`${fence}${maliciousValue}${fence}`);
    expect(markdown).not.toContain("## Canonical JSON");
  });

  test("renders deterministic Markdown from the canonical result without a second payment", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    const omni = createOmni();
    const app = createFixture(store, gateway, omni);
    const { url } = await listen(app);

    const json = await packageRequest(url, "11111111-1111-4111-8111-111111111120");
    const canonical = await json.json();
    const markdown = await packageRequest(url, "11111111-1111-4111-8111-111111111120", { payment: false, accept: "text/markdown" });

    expect(markdown.status).toBe(200);
    expect(markdown.headers.get("content-type")).toContain("text/markdown");
    expect(markdown.headers.get("vary")).toContain("Accept");
    expect(await markdown.text()).toBe(renderRiskMarkdown(canonical));
    expect(omni.calls).toBe(1);
    expect(gateway.settlementCount).toBe(1);
  });

  test("replays Markdown first and JSON second from one canonical completed result", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    const omni = createOmni();
    const app = createFixture(store, gateway, omni);
    const { url } = await listen(app);
    const key = "11111111-1111-4111-8111-111111111121";

    const markdown = await packageRequest(url, key, { accept: "text/markdown" });
    const json = await packageRequest(url, key, { payment: false, accept: "application/json" });

    expect(markdown.status).toBe(200);
    expect(markdown.headers.get("content-type")).toContain("text/markdown");
    expect(json.status).toBe(200);
    expect(json.headers.get("content-type")).toContain("application/json");
    expect(await json.json()).toMatchObject({ subject: { type: "package" }, riskScore: 3, recommendation: "proceed" });
    expect(omni.calls).toBe(1);
    expect(gateway.settlementCount).toBe(1);
  });

  test("renders dependency and x402 preflight Markdown from their canonical results", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    const packageAssessment = {
      subject: { type: "package", id: "npm:fixture@1.0.0" },
      recommendation: "proceed",
      riskScore: 3,
      evidenceCoverage: 1,
      dimensions: { packageSupplyChain: "low" },
      signals: [],
      evidence: [{ source: "fixture", kind: "registry", observedAt: "2026-08-25T00:00:00.000Z", detail: { verified: true } }],
      sourceErrors: [],
      freshness: { oldestEvidenceAt: null, newestEvidenceAt: null }
    };
    const omni = {
      async packageRisk() { return packageAssessment; },
      async dependenciesRisk() {
        return {
          packages: [packageAssessment],
          summary: { count: 1, worstRiskScore: 3, recommendations: { proceed: 1 } },
          assessedAt: "2026-08-25T00:00:00.000Z"
        };
      },
      async endpointPreflight() {
        return {
          ...packageAssessment,
          subject: { type: "x402_endpoint", id: "https://example.com/paid" },
          preflightContext: {
            resource: "https://example.com/paid",
            paymentOptions: [{ scheme: "exact", network: NETWORK, amount: "5000", asset: ASSET, payTo: SELLER, maxTimeoutSeconds: 300 }]
          }
        };
      }
    };
    const app = createApp({
      omni: omni as unknown as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway: gateway.asGateway(),
      paidRequests: store,
      circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"),
      maxInFlight: 32
    });
    const { url } = await listen(app);
    const dependencyResponse = await fetch(`${url}/v1/dependencies/risk`, {
      method: "POST",
      headers: { "content-type": "application/json", "Idempotency-Key": "11111111-1111-4111-8111-111111111124", Accept: "text/markdown", "PAYMENT-SIGNATURE": paymentHeader() },
      body: JSON.stringify({ packages: [PACKAGE_INPUT] })
    });
    const endpointResponse = await fetch(`${url}/v1/x402/endpoint/preflight?url=https%3A%2F%2Fexample.com%2Fpaid`, {
      headers: { "Idempotency-Key": "11111111-1111-4111-8111-111111111125", Accept: "text/markdown", "PAYMENT-SIGNATURE": paymentHeader() }
    });
    const dependencyMarkdown = await dependencyResponse.text();
    const endpointMarkdown = await endpointResponse.text();

    expect(dependencyResponse.status).toBe(200);
    expect(dependencyMarkdown).toContain("# OMNI Dependency Assessment");
    expect(dependencyMarkdown).toContain("Package Assessments");
    expect(dependencyMarkdown).toContain("npm:fixture@1.0.0");
    expect(endpointResponse.status).toBe(200);
    expect(endpointMarkdown).toContain("# OMNI Risk Assessment");
    expect(endpointMarkdown).toContain("Observed Preflight Context");
    expect(endpointMarkdown).toContain("https://example.com/paid");
    expect(endpointMarkdown).toContain("not payment authorization");
    expect(gateway.settlementCount).toBe(2);
  });

  test("keeps payment failures in the existing JSON error format", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    gateway.verificationFailure = true;
    const app = createFixture(store, gateway, createOmni());
    const { url } = await listen(app);

    const response = await packageRequest(url, PACKAGE_KEY, { accept: "text/markdown" });

    expect(response.status).toBe(402);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(await response.json()).toEqual({ error: "Payment verification failed" });
  });

  test("resumes an already-paid request without a new settlement", async () => {
    const store = new MemoryPaidRequestStore();
    store.seed(requestFor("paid"));
    const gateway = new TestGateway();
    const omni = createOmni();
    const app = createFixture(store, gateway, omni);
    const { url } = await listen(app);
    const response = await packageRequest(url, PACKAGE_KEY, { payment: false });
    expect(response.status).toBe(200);
    expect(omni.calls).toBe(1);
    expect(gateway.settlementCount).toBe(0);
    expect(store.rows.get(PACKAGE_KEY)?.state).toBe("completed");
  });

  test("keeps payment paid when OMNI throws and resumes on retry without payment", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    const omni = createOmni();
    omni.throwNext = true;
    const app = createFixture(store, gateway, omni);
    const { url } = await listen(app);
    expect((await packageRequest(url, PACKAGE_KEY)).status).toBe(500);
    expect(store.rows.get(PACKAGE_KEY)?.state).toBe("paid");
    const retry = await packageRequest(url, PACKAGE_KEY, { payment: false });
    expect(retry.status).toBe(200);
    expect(omni.calls).toBe(2);
    expect(gateway.settlementCount).toBe(1);
  });

  test("fails before payment when the durable store cannot claim", async () => {
    const store = new MemoryPaidRequestStore();
    store.failNext("get");
    const gateway = new TestGateway();
    const app = createFixture(store, gateway, createOmni());
    const { url } = await listen(app);
    const response = await packageRequest(url, PACKAGE_KEY);
    expect(response.status).toBe(503);
    expect(gateway.settlementCount).toBe(0);
  });

  test("keeps unpaid negotiation at 402 when the store lookup is unavailable", async () => {
    const store = new MemoryPaidRequestStore();
    store.failNext("get");
    const gateway = new TestGateway();
    const app = createFixture(store, gateway, createOmni());
    const { url } = await listen(app);
    const response = await packageRequest(url, PACKAGE_KEY, { payment: false });
    expect(response.status).toBe(402);
    expect(gateway.settlementCount).toBe(0);
  });

  test("resets a no-nonce settlement claim and allows a later paid retry to complete", async () => {
    const store = new MemoryPaidRequestStore();
    store.failNext("persistPaymentNonce");
    const gateway = new TestGateway();
    const app = createFixture(store, gateway, createOmni());
    const { url } = await listen(app);
    const first = await packageRequest(url, PACKAGE_KEY);
    expect(first.status).toBe(402);
    expect(gateway.settlementCount).toBe(0);
    expect(store.rows.get(PACKAGE_KEY)?.state).toBe("settling");

    const unpaidRetry = await packageRequest(url, PACKAGE_KEY, { payment: false });
    expect(unpaidRetry.status).toBe(402);
    expect(gateway.settlementCount).toBe(0);
    expect(store.rows.get(PACKAGE_KEY)?.state).toBe("waiting_payment");

    const paidRetry = await packageRequest(url, PACKAGE_KEY);
    expect(paidRetry.status).toBe(200);
    expect(gateway.settlementCount).toBe(1);
    expect(store.rows.get(PACKAGE_KEY)?.state).toBe("completed");
  });

  test("does not double-settle under concurrent paid retries", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    const omni = createOmni();
    const app = createFixture(store, gateway, omni);
    const { url } = await listen(app);
    const responses = await Promise.all([
      packageRequest(url, PACKAGE_KEY),
      packageRequest(url, PACKAGE_KEY)
    ]);
    expect(gateway.settlementCount).toBe(1);
    expect(gateway.settlementCount).toBeLessThanOrEqual(1);
    const statuses = responses.map(response => response.status).sort();
    expect(statuses[0]).toBe(200);
    expect(statuses[1] === 200 || statuses[1] === 409).toBe(true);
  });

  test("heartbeat prevents premature reclaim and a stopped heartbeat allows stale reclaim", async () => {
    const store = new MemoryPaidRequestStore();
    const gatewayA = new TestGateway();
    const gatewayB = new TestGateway();
    let resolveStarted!: () => void;
    let resolveExecution!: () => void;
    const started = new Promise<void>(resolve => { resolveStarted = resolve; });
    const finish = new Promise<void>(resolve => { resolveExecution = resolve; });
    let executionCountA = 0;
    let executionCountB = 0;
    const result = { subject: { type: "package", id: "npm:fixture@1.0.0" }, riskScore: 3, recommendation: "proceed" };
    const omniA = { async packageRisk() { executionCountA += 1; resolveStarted(); await finish; return result; } };
    const omniB = { async packageRisk() { executionCountB += 1; return result; } };
    const appA = createApp({ omni: omniA as unknown as OmniIntelligence, history: testHistory(), threatIntel: testThreatIntel(), gateway: gatewayA.asGateway(), paidRequests: store, circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"), maxInFlight: 32, executionLeaseMs: 60 });
    const appB = createApp({ omni: omniB as unknown as OmniIntelligence, history: testHistory(), threatIntel: testThreatIntel(), gateway: gatewayB.asGateway(), paidRequests: store, circleTransfers: new CircleTransferLookup("http://127.0.0.1:1"), maxInFlight: 32, executionLeaseMs: 60 });
    const workerA = await listen(appA);
    const workerB = await listen(appB);
    const firstRequest = packageRequest(workerA.url, PACKAGE_KEY);
    await started;
    await new Promise(resolve => setTimeout(resolve, 100));
    const concurrentRetry = await packageRequest(workerB.url, PACKAGE_KEY, { payment: false });
    expect(concurrentRetry.status).toBe(409);
    expect(executionCountA).toBe(1);
    expect(executionCountB).toBe(0);
    expect(gatewayA.settlementCount).toBe(1);
    resolveExecution();
    expect((await firstRequest).status).toBe(200);
    const replay = await packageRequest(workerB.url, PACKAGE_KEY, { payment: false });
    expect(replay.status).toBe(200);
    expect(executionCountA).toBe(1);
    expect(gatewayA.settlementCount).toBe(1);

    const staleKey = "11111111-1111-4111-8111-111111111116";
    const staleFingerprint = requestFingerprint("package", "GET", PACKAGE_INPUT);
    store.seed(requestFor("paid", { idempotencyKey: staleKey, requestFingerprint: staleFingerprint }));
    const staleClaim = await store.claimExecution(staleKey, staleFingerprint, 30);
    if (typeof staleClaim !== "object") throw new Error("stale worker lease missing");
    await new Promise(resolve => setTimeout(resolve, 70));
    const reclaimed = await store.claimExecution(staleKey, staleFingerprint, 30);
    expect(reclaimed).toMatchObject({ kind: "claimed" });
    if (typeof reclaimed !== "object") throw new Error("reclaimed lease missing");
    expect(reclaimed.leaseId).not.toBe(staleClaim.leaseId);
  });

  test("blocks OMNI after settlement when after-settle payment persistence fails, then recovers by nonce over real HTTP", async () => {
    const circle = await httpServer(request => new Response(JSON.stringify({ transfers: [{ id: "recovered-transfer", status: "completed", token: "USDC", sendingNetwork: NETWORK, recipientNetwork: NETWORK, fromAddress: PAYER, toAddress: SELLER, amount: "5000", nonce: NONCE, txHash: null }] }), { headers: { "content-type": "application/json" } }));
    const store = new MemoryPaidRequestStore();
    store.failNext("markPaid");
    const gateway = new TestGateway();
    const omni = createOmni();
    const app = createFixture(store, gateway, omni, circle.url);
    const { url } = await listen(app);
    const first = await packageRequest(url, PACKAGE_KEY);
    expect(first.status).toBe(503);
    expect(omni.calls).toBe(0);
    const retry = await packageRequest(url, PACKAGE_KEY, { payment: false });
    expect(retry.status).toBe(200);
    expect(omni.calls).toBe(1);
    expect(gateway.settlementCount).toBe(1);
    expect(circle.requests).toEqual([`GET /v1/x402/transfers?nonce=${encodeURIComponent(NONCE)}`]);
    expect(store.rows.get(PACKAGE_KEY)).toMatchObject({ state: "completed", circleTransferId: "recovered-transfer" });
  });

  test("releases paid execution after completed persistence failure so retry recomputes without payment", async () => {
    const store = new MemoryPaidRequestStore();
    store.failNext("complete");
    const gateway = new TestGateway();
    const omni = createOmni();
    const app = createFixture(store, gateway, omni);
    const { url } = await listen(app);
    expect((await packageRequest(url, PACKAGE_KEY)).status).toBe(500);
    expect(store.rows.get(PACKAGE_KEY)?.state).toBe("paid");
    const retry = await packageRequest(url, PACKAGE_KEY, { payment: false });
    expect(retry.status).toBe(200);
    expect(omni.calls).toBe(2);
    expect(gateway.settlementCount).toBe(1);
  });
});

describe("paid settlement reconciliation", () => {
  async function seededRecovery(circleResponse: unknown, circleStatus = 200): Promise<{ url: string; circle: { requests: string[] }; store: MemoryPaidRequestStore; gateway: TestGateway }> {
    const circle = await httpServer(() => new Response(JSON.stringify(circleResponse), { status: circleStatus, headers: { "content-type": "application/json" } }));
    const store = new MemoryPaidRequestStore();
    store.seed(requestFor("settling"));
    const gateway = new TestGateway();
    const app = createFixture(store, gateway, createOmni(), circle.url);
    const fixture = await listen(app);
    return { url: fixture.url, circle, store, gateway };
  }

  test("recovers an accepted exact transfer through a real local Circle HTTP lookup", async () => {
    const fixture = await seededRecovery({ transfers: [{ id: "accepted", status: "received", token: "USDC", sendingNetwork: NETWORK, recipientNetwork: NETWORK, fromAddress: PAYER, toAddress: SELLER, amount: "5000", nonce: NONCE, txHash: null }] });
    const response = await packageRequest(fixture.url, PACKAGE_KEY, { payment: false });
    expect(response.status).toBe(200);
    expect(fixture.gateway.settlementCount).toBe(0);
    expect(fixture.store.rows.get(PACKAGE_KEY)).toMatchObject({ state: "completed", circleTransferId: "accepted" });
    expect(fixture.circle.requests).toHaveLength(1);
  });

  test("can recover a later accepted transfer after an earlier lookup was unknown", async () => {
    const firstCircle = await httpServer(() => new Response(JSON.stringify({ transfers: [] }), { headers: { "content-type": "application/json" } }));
    const store = new MemoryPaidRequestStore();
    store.seed(requestFor("settling"));
    const gateway = new TestGateway();
    const app = createFixture(store, gateway, createOmni(), firstCircle.url);
    const first = await listen(app);
    expect((await packageRequest(first.url, PACKAGE_KEY, { payment: false })).status).toBe(503);
    expect(store.rows.get(PACKAGE_KEY)?.state).toBe("recovery_pending");

    const secondCircle = await httpServer(() => new Response(JSON.stringify({ transfers: [{ id: "late-accepted", status: "completed", token: "USDC", sendingNetwork: NETWORK, recipientNetwork: NETWORK, fromAddress: PAYER, toAddress: SELLER, amount: "5000", nonce: NONCE, txHash: null }] }), { headers: { "content-type": "application/json" } }));
    const recoveryApp = createFixture(store, gateway, createOmni(), secondCircle.url);
    const recovery = await listen(recoveryApp);
    const response = await packageRequest(recovery.url, PACKAGE_KEY, { payment: false });
    expect(response.status).toBe(200);
    expect(gateway.settlementCount).toBe(0);
    expect(store.rows.get(PACKAGE_KEY)).toMatchObject({ state: "completed", circleTransferId: "late-accepted" });
  });

  test.each([
    ["no result", { transfers: [] }, 503],
    ["wrong amount", { transfers: [{ id: "wrong-amount", status: "completed", token: "USDC", sendingNetwork: NETWORK, recipientNetwork: NETWORK, fromAddress: PAYER, toAddress: SELLER, amount: "5001", nonce: NONCE, txHash: null }] }, 503],
    ["wrong recipient", { transfers: [{ id: "wrong-recipient", status: "completed", token: "USDC", sendingNetwork: NETWORK, recipientNetwork: NETWORK, fromAddress: PAYER, toAddress: "0x4444444444444444444444444444444444444444", amount: "5000", nonce: NONCE, txHash: null }] }, 503],
    ["lookup unavailable", { error: "unavailable" }, 503]
  ] as const)("fails closed for %s with no second payment", async (_label, body, expectedStatus) => {
    const fixture = await seededRecovery(body, _label === "lookup unavailable" ? 503 : 200);
    const response = await packageRequest(fixture.url, PACKAGE_KEY, { payment: false });
    expect(response.status).toBe(expectedStatus);
    expect(fixture.gateway.settlementCount).toBe(0);
    expect(fixture.store.rows.get(PACKAGE_KEY)?.state).toBe("recovery_pending");
  });

  test("does not convert nonce_already_used into paid without transfer reconciliation", async () => {
    const store = new MemoryPaidRequestStore();
    const gateway = new TestGateway();
    gateway.settlementResult = { success: false, errorReason: "nonce_already_used" };
    const app = createFixture(store, gateway, createOmni());
    const { url } = await listen(app);
    expect((await packageRequest(url, PACKAGE_KEY)).status).toBe(402);
    expect(gateway.settlementCount).toBe(1);
    const circle = await httpServer(() => new Response(JSON.stringify({ transfers: [] }), { headers: { "content-type": "application/json" } }));
    const recoveryApp = createFixture(store, new TestGateway(), createOmni(), circle.url);
    const recovery = await listen(recoveryApp);
    const retry = await packageRequest(recovery.url, PACKAGE_KEY, { payment: false });
    expect(retry.status).toBe(503);
    expect(store.rows.get(PACKAGE_KEY)?.state).toBe("recovery_pending");
  });

  test("treats an exact failed transfer as payment_failed without a second settlement", async () => {
    const fixture = await seededRecovery({ transfers: [{ id: "failed", status: "failed", token: "USDC", sendingNetwork: NETWORK, recipientNetwork: NETWORK, fromAddress: PAYER, toAddress: SELLER, amount: "5000", nonce: NONCE, txHash: null }] });
    const response = await packageRequest(fixture.url, PACKAGE_KEY, { payment: false });
    expect(response.status).toBe(402);
    expect(await response.json()).toEqual({ error: "payment_failed", retryable: false });
    expect(fixture.gateway.settlementCount).toBe(0);
  });
});

describe("installed Circle Gateway middleware lifecycle", () => {
  async function facilitator(settleCalls: { value: number }) {
    return httpServer(request => {
      const url = new URL(request.url);
      if (url.pathname === "/v1/x402/supported") {
        return new Response(JSON.stringify({ kinds: [{ x402Version: 2, scheme: "exact", network: NETWORK, extra: { verifyingContract: SELLER, assets: [{ symbol: "USDC", address: ASSET }] } }], extensions: [], signers: {} }), { headers: { "content-type": "application/json" } });
      }
      if (url.pathname === "/v1/x402/verify") {
        return new Response(JSON.stringify({ isValid: true, payer: PAYER }), { headers: { "content-type": "application/json" } });
      }
      if (url.pathname === "/v1/x402/settle") {
        settleCalls.value += 1;
        return new Response(JSON.stringify({ success: true, transaction: "sdk-transfer", network: NETWORK, payer: PAYER }), { headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify({ error: "not found" }), { status: 404, headers: { "content-type": "application/json" } });
    });
  }

  test("v3.3.0 onBeforeSettle abort returns before facilitator.settle", async () => {
    const settleCalls = { value: 0 };
    const circle = await facilitator(settleCalls);
    const gateway = createGatewayMiddleware({ sellerAddress: SELLER, facilitatorUrl: circle.url });
    gateway.onBeforeSettle(async () => ({ abort: true, reason: "durable_claim_failed" }));
    const app = express();
    app.get("/paid", gateway.require("$0.005"), (_req, res) => res.json({ reached: true }));
    const fixture = await listen(app);
    const response = await fetch(`${fixture.url}/paid`, { headers: { "PAYMENT-SIGNATURE": paymentHeader() } });
    expect(response.status).toBe(402);
    expect(settleCalls.value).toBe(0);
  });

  test("v3.3.0 onAfterSettle errors are swallowed and next handler runs", async () => {
    const settleCalls = { value: 0 };
    const circle = await facilitator(settleCalls);
    const gateway = createGatewayMiddleware({ sellerAddress: SELLER, facilitatorUrl: circle.url });
    gateway.onAfterSettle(async () => { throw new Error("injected after-settle failure"); });
    const app = express();
    app.get("/paid", gateway.require("$0.005"), (_req, res) => res.json({ reached: true }));
    const fixture = await listen(app);
    const response = await fetch(`${fixture.url}/paid`, { headers: { "PAYMENT-SIGNATURE": paymentHeader() } });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ reached: true });
    expect(settleCalls.value).toBe(1);
  });

  test("actual SDK and PaidRouteIntegration preserve nonce, settlement, execution, completion, and replay ordering", async () => {
    const settleCalls = { value: 0 };
    const circle = await facilitator(settleCalls);
    const store = new MemoryPaidRequestStore();
    const gateway = createGatewayMiddleware({ sellerAddress: SELLER, facilitatorUrl: circle.url });
    const omni = {
      calls: 0,
      async packageRisk() {
        omni.calls += 1;
        store.events.push("omni");
        return { subject: { type: "package", id: "npm:fixture@1.0.0" }, riskScore: 3, recommendation: "proceed" };
      }
    };
    const app = createApp({
      omni: omni as unknown as OmniIntelligence,
      history: testHistory(),
      threatIntel: testThreatIntel(),
      gateway,
      paidRequests: store,
      circleTransfers: new CircleTransferLookup(circle.url, 500),
      maxInFlight: 32
    });
    const fixture = await listen(app);
    const first = await packageRequest(fixture.url, PACKAGE_KEY);
    const firstBody = await first.json();
    expect(first.status).toBe(200);
    expect(first.headers.get("PAYMENT-RESPONSE")).not.toBeNull();
    expect(settleCalls.value).toBe(1);
    expect(omni.calls).toBe(1);
    expect(store.events).toEqual(["nonce_persisted", "paid", "omni", "completed"]);
    expect(store.rows.get(PACKAGE_KEY)?.state).toBe("completed");

    const replay = await packageRequest(fixture.url, PACKAGE_KEY, { payment: false });
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual(firstBody);
    expect(settleCalls.value).toBe(1);
    expect(omni.calls).toBe(1);
  });
});
