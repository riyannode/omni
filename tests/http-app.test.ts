import { afterEach, describe, expect, test } from "bun:test";
import type { AddressInfo } from "node:net";
import type { RequestHandler } from "express";
import { createApp } from "../src/http/app.ts";
import type { HistoryStore } from "../src/data/history.ts";
import type { ThreatIntelStore } from "../src/data/threat-intel.ts";
import type { OmniIntelligence } from "../src/services.ts";

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
  });
});
