import { afterEach, describe, expect, mock, test } from "bun:test";
import { createCircleDiscovery, clearPaidResourcesCache } from "../src/payments/circle.ts";
import { BatchFacilitatorClient } from "@circle-fin/x402-batching/server";

const originalGetSupported = BatchFacilitatorClient.prototype.getSupported;
const originalDateNow = Date.now;

afterEach(() => {
  BatchFacilitatorClient.prototype.getSupported = originalGetSupported;
  Date.now = originalDateNow;
  clearPaidResourcesCache();
});

describe("createCircleDiscovery TTL cache", () => {
  test("first call invokes upstream once", async () => {
    const calls = { count: 0 };
    BatchFacilitatorClient.prototype.getSupported = mock(async () => {
      calls.count++;
      return {
        kinds: [
          { x402Version: 2, scheme: "exact", network: "eip155:8453" },
          { x402Version: 2, scheme: "exact", network: "eip155:1" }
        ],
        extensions: [],
        signers: {}
      };
    });

    const discovery = createCircleDiscovery("http://mock");
    const result = await discovery.getNetworks();
    expect(result).toEqual(["eip155:1", "eip155:8453"]);
    expect(calls.count).toBe(1);
  });

  test("second call within TTL does NOT invoke upstream again", async () => {
    const calls = { count: 0 };
    BatchFacilitatorClient.prototype.getSupported = mock(async () => {
      calls.count++;
      return {
        kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:8453" }],
        extensions: [],
        signers: {}
      };
    });

    const discovery = createCircleDiscovery("http://mock");
    await discovery.getNetworks();
    await discovery.getNetworks();
    await discovery.getNetworks();
    expect(calls.count).toBe(1);
  });

  test("failure without cache rejects with discovery unavailable", async () => {
    BatchFacilitatorClient.prototype.getSupported = mock(async () => {
      throw new Error("gateway unavailable");
    });

    const discovery = createCircleDiscovery("http://mock");
    await expect(discovery.getNetworks()).rejects.toThrow("circle_gateway_discovery_unavailable");
  });

  test("expired cache triggers new upstream discovery attempt", async () => {
    const calls = { count: 0 };
    let networks: string[] = ["eip155:8453"];
    let mockTime = 1_000_000;

    BatchFacilitatorClient.prototype.getSupported = mock(async () => {
      calls.count++;
      return {
        kinds: networks.map(n => ({ x402Version: 2, scheme: "exact", network: n })),
        extensions: [],
        signers: {}
      };
    });

    Date.now = () => mockTime;

    const discovery = createCircleDiscovery("http://mock");

    // First call: upstream invoked
    const first = await discovery.getNetworks();
    expect(first).toEqual(["eip155:8453"]);
    expect(calls.count).toBe(1);

    // Within TTL: no new upstream call
    mockTime = 1_000_000 + 100_000; // 100s later, still within 300s TTL
    const second = await discovery.getNetworks();
    expect(second).toEqual(["eip155:8453"]);
    expect(calls.count).toBe(1);

    // After TTL expires: new upstream call
    mockTime = 1_000_000 + 300_001; // 300s + 1ms later, TTL expired
    networks = ["eip155:1", "eip155:8453"]; // Gateway returns new networks
    const third = await discovery.getNetworks();
    expect(third).toEqual(["eip155:1", "eip155:8453"]);
    expect(calls.count).toBe(2);
  });

  test("upstream failure after cache expired but still within stale window returns stale cache", async () => {
    // Note: current implementation returns stale cache on failure regardless of TTL
    // This test documents that behavior
    const calls = { count: 0 };
    let mockTime = 1_000_000;

    BatchFacilitatorClient.prototype.getSupported = mock(async () => {
      calls.count++;
      if (calls.count === 1) {
        return {
          kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:8453" }],
          extensions: [],
          signers: {}
        };
      }
      throw new Error("gateway unavailable");
    });

    Date.now = () => mockTime;

    const discovery = createCircleDiscovery("http://mock");

    // First call: upstream invoked, cache populated
    const first = await discovery.getNetworks();
    expect(first).toEqual(["eip155:8453"]);
    expect(calls.count).toBe(1);

    // After TTL expires + upstream fails: returns stale cache
    mockTime = 1_000_000 + 600_001; // 10 minutes later
    const second = await discovery.getNetworks();
    expect(second).toEqual(["eip155:8453"]); // stale cache returned
    expect(calls.count).toBe(2);
  });

  test("filters out non-v2, non-exact, and empty networks", async () => {
    BatchFacilitatorClient.prototype.getSupported = mock(async () => ({
      kinds: [
        { x402Version: 2, scheme: "exact", network: "eip155:8453" },
        { x402Version: 2, scheme: "exact", network: "eip155:1" },
        { x402Version: 1, scheme: "exact", network: "eip155:1" }, // wrong version
        { x402Version: 2, scheme: "probabilistic", network: "eip155:137" }, // wrong scheme
        { x402Version: 2, scheme: "exact", network: "" }, // empty
        { x402Version: 2, scheme: "exact", network: "  " }, // whitespace
        { x402Version: 2, scheme: "exact", network: "eip155:8453" } // duplicate
      ],
      extensions: [],
      signers: {}
    }));

    const discovery = createCircleDiscovery("http://mock");
    const result = await discovery.getNetworks();
    expect(result).toEqual(["eip155:1", "eip155:8453"]);
  });
});

describe("createCircleDiscovery cache isolation", () => {
  test("returns copies that cannot mutate internal cache", async () => {
    BatchFacilitatorClient.prototype.getSupported = mock(async () => ({
      kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:8453" }],
      extensions: [],
      signers: {}
    }));

    const discovery = createCircleDiscovery("http://mock");
    const first = await discovery.getNetworks();
    first.push("injected");

    const second = await discovery.getNetworks();
    expect(second).toEqual(["eip155:8453"]);
    expect(second).not.toContain("injected");
  });

  test("separate discovery instances have separate caches", async () => {
    const calls1 = { count: 0 };
    BatchFacilitatorClient.prototype.getSupported = mock(async () => {
      calls1.count++;
      return {
        kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:8453" }],
        extensions: [],
        signers: {}
      };
    });

    const discovery1 = createCircleDiscovery("http://mock");
    const discovery2 = createCircleDiscovery("http://mock");

    await discovery1.getNetworks();
    await discovery2.getNetworks();

    expect(calls1.count).toBe(2); // Each instance has its own cache
  });
});
