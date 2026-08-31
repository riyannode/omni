import { afterEach, expect, test } from "bun:test";
import https from "node:https";
import { readFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { UpstreamAdmission, UpstreamHttp } from "../src/providers/http.ts";
import { PinnedHttpsTransport } from "../src/providers/pinned-https.ts";
import { PublicNetworkPolicy } from "../src/providers/public-network.ts";
import { X402Probe } from "../src/providers/x402-probe.ts";

const keyPath = process.env.PINNED_TEST_KEY;
const certPath = process.env.PINNED_TEST_CERT;
const realTlsTest = test.if(Boolean(keyPath && certPath));
const servers: https.Server[] = [];
const paymentHeader = Buffer.from(JSON.stringify({ accepts: [] })).toString("base64");

async function listen(mode: "large" | "trickle"): Promise<{ server: https.Server; url: string }> {
  if (!keyPath || !certPath) throw new Error("TLS test certificate missing");
  const server = https.createServer({ key: await readFile(keyPath), cert: await readFile(certPath) }, (_request, response) => {
    response.writeHead(402, { "PAYMENT-REQUIRED": paymentHeader, "content-type": "text/plain" });
    if (mode === "large") {
      response.end(Buffer.alloc(32 * 1024, "x"));
      return;
    }
    response.write("x");
    const timer = setInterval(() => response.write("x"), 25);
    response.on("close", () => clearInterval(timer));
  });
  servers.push(server);
  await new Promise<void>((resolve, reject) => { server.listen(0, "127.0.0.1", () => resolve()); server.once("error", reject); });
  return { server, url: `https://x402.test:${(server.address() as AddressInfo).port}/` };
}

afterEach(async () => { await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve())))); });

realTlsTest("x402 discard mode reads PAYMENT-REQUIRED before a 32 KiB body completes", async () => {
  const { url } = await listen("large");
  const http = new UpstreamHttp(2000, 4, 4);
  const network = { resolveAndValidate: async () => [{ address: "127.0.0.1", family: 4 as const }] } as unknown as PublicNetworkPolicy;
  const probe = new X402Probe(http, network, new PinnedHttpsTransport(2000, undefined, http.getAdmission()));
  const result = await probe.unpaidGet(url);
  expect(result.status).toBe(402);
  expect(result.evidence.detail.paymentOptions).toBe(0);
});

realTlsTest("x402 discard mode returns from a trickling body without waiting for completion", async () => {
  const { url } = await listen("trickle");
  const http = new UpstreamHttp(2000, 4, 4);
  const network = { resolveAndValidate: async () => [{ address: "127.0.0.1", family: 4 as const }] } as unknown as PublicNetworkPolicy;
  const probe = new X402Probe(http, network, new PinnedHttpsTransport(2000, undefined, http.getAdmission()));
  const started = Date.now();
  const result = await probe.unpaidGet(url);
  expect(result.status).toBe(402);
  expect(Date.now() - started).toBeLessThan(500);
});

test("shared upstream admission caps concurrent pinned outbound operations", async () => {
  const admission = new UpstreamAdmission(2, 8);
  let active = 0;
  let peak = 0;
  const transport = new PinnedHttpsTransport(1000, async () => {
    active += 1;
    peak = Math.max(peak, active);
    await Bun.sleep(10);
    active -= 1;
    return { statusCode: 200, headers: new Headers(), body: new Uint8Array(), tls: { authorized: true, hostnameMatch: true } };
  }, admission);
  await Promise.all(Array.from({ length: 8 }, () => transport.request(new URL("https://example.com/"), { address: "93.184.216.34", family: 4 }, { method: "GET", tlsMode: "strict", responseBodyMode: "bounded", maximumBodyBytes: 1024, headers: {} })));
  expect(peak).toBe(2);
});
