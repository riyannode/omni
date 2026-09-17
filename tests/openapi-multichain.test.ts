import { describe, expect, test } from "bun:test";
import { parse } from "yaml";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const openapiPath = resolve(import.meta.dirname, "..", "openapi.yaml");
const spec = parse(readFileSync(openapiPath, "utf8")) as any;

const PAID_ROUTES = [
  { path: "/v1/package/risk", method: "get" },
  { path: "/v1/repo/risk", method: "get" },
  { path: "/v1/dependencies/risk", method: "post" },
  { path: "/v1/x402/endpoint/preflight", method: "get" },
];

const ARC_MAINNET = "eip155:5042";
const ARC_TESTNET = "eip155:5042002";

describe("OpenAPI x402 multi-chain discovery metadata", () => {
  test("all paid operations have x-payment-info", () => {
    for (const { path, method } of PAID_ROUTES) {
      const op = spec.paths[path]?.[method];
      expect(op).toBeDefined();
      expect(op["x-payment-info"]).toBeDefined();
    }
  });

  test("all paid operations have x402 network metadata", () => {
    for (const { path, method } of PAID_ROUTES) {
      const op = spec.paths[path]?.[method];
      const paymentInfo = op["x-payment-info"];
      const protocols = paymentInfo.protocols;
      expect(protocols).toBeDefined();
      const x402Entry = protocols.find((p: any) => p.x402 !== undefined);
      expect(x402Entry).toBeDefined();
      expect(x402Entry.x402.networks).toBeDefined();
      expect(Array.isArray(x402Entry.x402.networks)).toBe(true);
    }
  });

  test("every paid operation exposes >=2 distinct networks", () => {
    for (const { path, method } of PAID_ROUTES) {
      const op = spec.paths[path]?.[method];
      const networks = op["x-payment-info"].protocols.find((p: any) => p.x402).x402.networks;
      const distinct = new Set(networks);
      expect(distinct.size).toBeGreaterThanOrEqual(2);
    }
  });

  test("Arc Mainnet eip155:5042 is present on every paid operation", () => {
    for (const { path, method } of PAID_ROUTES) {
      const op = spec.paths[path]?.[method];
      const networks = op["x-payment-info"].protocols.find((p: any) => p.x402).x402.networks;
      expect(networks).toContain(ARC_MAINNET);
    }
  });

  test("Arc Testnet eip155:5042002 is absent on every paid operation", () => {
    for (const { path, method } of PAID_ROUTES) {
      const op = spec.paths[path]?.[method];
      const networks = op["x-payment-info"].protocols.find((p: any) => p.x402).x402.networks;
      expect(networks).not.toContain(ARC_TESTNET);
    }
  });

  test("no testnet identifiers are present on any paid operation", () => {
    const testnetPatterns = [
      "sepolia",
      "fuji",
      "amoy",
      "devnet",
      "testnet",
      "11155111",
      "84532",
      "80002",
      "421614",
      "11155420",
      "5042002",
      "14601",
      "901",
      "1287",
      "80084",
      "43524",
    ];
    for (const { path, method } of PAID_ROUTES) {
      const op = spec.paths[path]?.[method];
      const networks = op["x-payment-info"].protocols.find((p: any) => p.x402).x402.networks;
      for (const pattern of testnetPatterns) {
        for (const net of networks) {
          expect(net.toLowerCase()).not.toContain(pattern);
        }
      }
    }
  });
});
