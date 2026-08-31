import { describe, expect, test } from "bun:test";
import { UrlRiskEngine } from "../src/domain/url-risk-engine.ts";
import { normalizeUrlRiskTarget, type UrlRiskSnapshot } from "../src/domain/url-risk.ts";
import { UpstreamAdmission, UpstreamHttp } from "../src/providers/http.ts";
import { PinnedHttpsTransport } from "../src/providers/pinned-https.ts";
import { PublicNetworkPolicy } from "../src/providers/public-network.ts";
import { UrlHttpProbe } from "../src/providers/url-http-probe.ts";
import { X402_REQUEST_POLICY, X402Probe } from "../src/providers/x402-probe.ts";
import { DEFAULT_URL_RISK_POLICY } from "../src/domain/url-risk-policy.ts";
import type { ResolvedPublicAddress } from "../src/providers/public-network.ts";
import type { PinnedHttpsResponse } from "../src/providers/pinned-https.ts";

function snapshot(overrides: Partial<UrlRiskSnapshot> = {}): UrlRiskSnapshot {
  return {
    subject: { type: "url", id: "https://example.com/" }, url: "https://example.com/", hostname: "example.com",
    threatIntelChecked: true, threatFindings: [], evidence: [], sourceErrors: [], ...overrides
  };
}

describe("UrlRiskEngine", () => {
  test("treats a critical Phishing.Database match as do_not_proceed", () => {
    const result = new UrlRiskEngine().assess(snapshot({ threatFindings: [{ indicatorType: "hostname", indicator: "example.com", threatType: "phishing", severity: "critical", source: "phishing_database" }] }));
    expect(result.policyVersion).toBe("omni-url-risk-v1"); expect(result.recommendation).toBe("do_not_proceed");
    expect(result.urlDimensions.threatReputation).toBe("critical"); expect(result.signals[0]?.source).toBe("phishing_database");
  });

  test("keeps weak URL signals below malicious classification", () => {
    const result = new UrlRiskEngine().assess(snapshot({
      rdap: { status: "registered", events: [{ eventAction: "registration", eventDate: "2026-08-01T00:00:00Z" }] },
      tls: { status: "valid", authorized: true, hostnameMatch: true },
      http: { status: "observed", statusCode: 200, redirects: [{ from: "https://example.com/", to: "https://www.example.com/", statusCode: 301 }], securityHeaders: { hsts: false, contentSecurityPolicy: false, xContentTypeOptions: false } }
    }));
    expect(result.recommendation).not.toBe("do_not_proceed"); expect(result.urlDimensions.domainIdentity).toBe("low"); expect(result.urlDimensions.transportSecurity).toBe("low");
  });

  test("makes source failures explicit and lowers coverage without inventing a threat match", () => {
    const result = new UrlRiskEngine().assess(snapshot({ threatIntelChecked: false, sourceErrors: ["RDAP: unavailable", "TLS: timeout"] }));
    expect(result.sourceErrors).toEqual(["RDAP: unavailable", "TLS: timeout"]); expect(result.evidenceCoverage).toBeLessThan(1);
    expect(result.urlDimensions.threatReputation).toBe("unknown"); expect(result.signals.some(signal => signal.code === "THREAT_INTELLIGENCE_MATCH")).toBe(false);
  });

  test("treats RDAP not_found as unknown without changing the score", () => {
    const registered = new UrlRiskEngine().assess(snapshot({ rdap: { status: "registered" } }));
    const notFound = new UrlRiskEngine().assess(snapshot({ rdap: { status: "not_found" } }));
    expect(registered.urlDimensions.domainIdentity).toBe("low");
    expect(notFound.urlDimensions.domainIdentity).toBe("unknown");
    expect(notFound.riskScore).toBe(registered.riskScore);
  });
});

describe("PublicNetworkPolicy", () => {
  test("rejects every resolved address when any candidate is not globally routable", async () => {
    const policy = new PublicNetworkPolicy(async () => [{ address: "93.184.216.34", family: 4 }, { address: "169.254.169.254", family: 4 }]);
    await expect(policy.resolveAndValidate("example.com")).rejects.toThrow("disallowed");
  });

  test("rejects localhost, loopback, RFC1918, link-local, metadata, multicast, and reserved IPv4", async () => {
    for (const address of ["localhost", "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.1.1", "169.254.169.254", "224.0.0.1", "192.0.2.1", "192.88.99.1", "198.51.100.1", "203.0.113.1"]) {
      await expect(new PublicNetworkPolicy().resolveAndValidate(address)).rejects.toThrow("disallowed");
    }
  });

  test("rejects IPv6 loopback, unique-local, link-local, multicast, unspecified, documentation, and mapped addresses", async () => {
    for (const address of ["::1", "fc00::1", "fe80::1", "fec0::1", "ff02::1", "::", "2001:db8::1", "::ffff:192.168.0.1"]) {
      const policy = new PublicNetworkPolicy(async () => [{ address, family: 6 }]);
      await expect(policy.resolveAndValidate("example.com")).rejects.toThrow("disallowed");
    }
  });

  test("keeps IANA globally reachable special-purpose ranges usable", async () => {
    for (const [address, family] of [["192.0.0.9", 4], ["192.0.0.10", 4], ["192.31.196.1", 4], ["192.52.193.1", 4], ["192.175.48.1", 4], ["64:ff9b::0808:0808", 6], ["2001:1::1", 6], ["2001:1::2", 6], ["2001:1::3", 6], ["2001:3::1", 6], ["2001:4:112::1", 6], ["2001:20::1", 6], ["2001:30::1", 6]] as const) {
      const policy = new PublicNetworkPolicy(async () => [{ address, family }]);
      await expect(policy.resolveAndValidate("example.com")).resolves.toEqual([{ address, family }]);
    }
  });

  test("fails closed for reserved IPv6 space and non-public NAT64 destinations", async () => {
    const rejected = [
      "400::1", "800::1", "1000::1", "::1", "fc00::1", "fe80::1", "fec0::1", "ff02::1", "::", "2001:db8::1",
      "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::0a00:1"
    ];
    for (const address of rejected) {
      const policy = new PublicNetworkPolicy(async () => [{ address, family: 6 }]);
      await expect(policy.resolveAndValidate("example.com")).rejects.toThrow("disallowed");
    }
    const publicGua = new PublicNetworkPolicy(async () => [{ address: "2606:4700:4700::1111", family: 6 }]);
    await expect(publicGua.resolveAndValidate("example.com")).resolves.toEqual([{ address: "2606:4700:4700::1111", family: 6 }]);
  });

  test("denies non-exception addresses within IANA 2001::/23", async () => {
    for (const address of ["2001:1::4", "2001:5::1"]) {
      const policy = new PublicNetworkPolicy(async () => [{ address, family: 6 }]);
      await expect(policy.resolveAndValidate("example.com")).rejects.toThrow("disallowed");
    }
  });

  test("normalizes bracketed IPv6 literals before classification", async () => {
    await expect(new PublicNetworkPolicy().resolveAndValidate("[2001:db8::1]")).rejects.toThrow("disallowed");
    await expect(new PublicNetworkPolicy().resolveAndValidate("[2001:1::1]")).resolves.toEqual([{ address: "2001:1::1", family: 6 }]);
    expect(normalizeUrlRiskTarget("https://[2001:1::1]/").hostname).toBe("[2001:1::1]");
  });
});

test("PinnedHttpsTransport connects to the validated address with original hostname identity", async () => {
  const calls: Array<{ hostname: string; servername: string; address: string; host: string }> = [];
  const transport = new PinnedHttpsTransport(1000, async options => {
    calls.push({ hostname: options.hostname, servername: options.servername, address: options.address, host: options.headers.host! });
    return { statusCode: 200, headers: new Headers({ "content-type": "text/plain" }), body: new Uint8Array(), tls: { authorized: true, hostnameMatch: true } };
  });
  await transport.request(new URL("https://example.com/path"), { address: "93.184.216.34", family: 4 }, { method: "GET", tlsMode: "strict", responseBodyMode: "bounded", maximumBodyBytes: 1024, headers: { accept: "application/json" } });
  expect(calls).toEqual([{ hostname: "example.com", servername: "example.com", address: "93.184.216.34", host: "example.com" }]);
});

test("PinnedHttpsTransport rejects non-HTTPS URLs before invoking the executor", async () => {
  let calls = 0;
  const transport = new PinnedHttpsTransport(1000, async () => {
    calls += 1;
    throw new Error("must not connect");
  });
  await expect(transport.request(new URL("http://example.com/"), { address: "93.184.216.34", family: 4 }, { method: "GET", tlsMode: "strict", responseBodyMode: "bounded", maximumBodyBytes: 1024, headers: {} })).rejects.toThrow("https");
  expect(calls).toBe(0);
});

test("X402Probe rejects HTTP before DNS or transport", async () => {
  let resolved = 0;
  const http = new UpstreamHttp(1000, 8, 8);
  const network = new PublicNetworkPolicy(async () => { resolved += 1; return [{ address: "93.184.216.34", family: 4 }]; });
  const probe = new X402Probe(http, network);
  await expect(probe.unpaidGet("http://example.com/")).rejects.toThrow("https");
  expect(resolved).toBe(0);
});

test("x402 probe keeps a strict TLS and JSON request profile", () => {
  expect(X402_REQUEST_POLICY).toEqual({ method: "GET", tlsMode: "strict", responseBodyMode: "discard", maximumBodyBytes: 8192, headers: { "user-agent": "OMNI/0.2 x402-preflight", accept: "application/json" } });
});

test("PinnedHttpsTransport enforces an absolute deadline around a stalled executor", async () => {
  const transport = new PinnedHttpsTransport(20, async options => await new Promise((_, reject) => options.signal.addEventListener("abort", () => reject(options.signal.reason), { once: true })));
  await expect(transport.request(new URL("https://example.com/"), { address: "93.184.216.34", family: 4 }, { method: "GET", tlsMode: "strict", responseBodyMode: "bounded", maximumBodyBytes: 1024, headers: {} })).rejects.toThrow("deadline");
});

test("PinnedHttpsTransport keeps admission occupied until a timed-out executor cleans up", async () => {
  let first = true;
  let active = 0;
  let peak = 0;
  const admission = new UpstreamAdmission(1, 1);
  const transport = new PinnedHttpsTransport(20, async options => {
    active += 1;
    peak = Math.max(peak, active);
    try {
      if (first) {
        first = false;
        await new Promise((_, reject) => options.signal.addEventListener("abort", () => reject(options.signal.reason), { once: true }));
      }
      return { statusCode: 200, headers: new Headers(), body: new Uint8Array(), tls: { authorized: true, hostnameMatch: true } };
    } finally {
      active -= 1;
    }
  }, admission);
  const request = { method: "GET" as const, tlsMode: "strict" as const, responseBodyMode: "bounded" as const, maximumBodyBytes: 1024, headers: {} };
  await expect(transport.request(new URL("https://example.com/first"), { address: "93.184.216.34", family: 4 }, request)).rejects.toThrow("deadline");
  await transport.request(new URL("https://example.com/second"), { address: "93.184.216.34", family: 4 }, request);
  expect(peak).toBe(1);
});

test("URL transport uses the stronger TLS downgrade score when both transport signals exist", () => {
  const result = new UrlRiskEngine().assess(snapshot({
    tls: { status: "invalid" },
    http: { status: "blocked", httpsDowngradeBlocked: true, redirects: [], securityHeaders: {} }
  }));
  expect(result.riskScore).toBe(60);
});

test("preserves the existing URL v1 policy values after extraction", () => {
  expect(DEFAULT_URL_RISK_POLICY).toEqual({
    version: "omni-url-risk-v1",
    severityWeights: { unknown: 0, low: 35, medium: 60, high: 85, critical: 100 },
    scoreLevelThresholds: { medium: 25, high: 50, critical: 80 },
    recommendationThresholds: { caution: 25, manualReview: 50, doNotProceed: 80 },
    transport: { tlsInvalid: 35, httpsDowngrade: 60 },
    network: { serverError: 15, multipleRedirects: 10 },
    sourceError: { perError: 5, cap: 20 },
    score: { maximum: 100, zeroCoverageFloor: 50 }
  });
});

test("deeply freezes the URL risk policy", () => {
  const policy = DEFAULT_URL_RISK_POLICY as unknown as { network: { serverError: number } };
  expect(() => { policy.network.serverError = 99; }).toThrow();
  expect(DEFAULT_URL_RISK_POLICY.network.serverError).toBe(15);
});

function response(statusCode: number, location?: string): PinnedHttpsResponse { return { statusCode, headers: new Headers(location ? { location } : {}), body: new Uint8Array(), tls: { authorized: true, hostnameMatch: true } }; }

test("UrlHttpProbe revalidates redirect targets and never connects to a rejected target", async () => {
  const addresses: ResolvedPublicAddress = { address: "93.184.216.34", family: 4 };
  const resolved: string[] = [];
  const policy = { resolveAndValidate: async (hostname: string) => { resolved.push(hostname); if (hostname === "private.example") throw new Error("disallowed network target"); return [addresses]; } };
  const requests: string[] = [];
  const transport = { request: async (url: URL) => { requests.push(url.toString()); return response(302, "https://private.example/"); } };
  await expect(new UrlHttpProbe(policy, transport).observe(new URL("https://example.com/"))).rejects.toThrow("disallowed network target");
  expect(resolved).toEqual(["example.com", "private.example"]); expect(requests).toEqual(["https://example.com/"]);
});

test("UrlHttpProbe records an HTTPS downgrade and does not follow it", async () => {
  const policy = { resolveAndValidate: async () => [{ address: "93.184.216.34", family: 4 as const }] };
  const observation = await new UrlHttpProbe(policy, { request: async () => response(301, "http://example.com/login") }).observe(new URL("https://example.com/"));
  expect(observation.httpsDowngradeBlocked).toBe(true);
  expect(observation.redirects).toEqual([{ from: "https://example.com/", to: "http://example.com/login", statusCode: 301 }]);
});

test("UrlHttpProbe stops an excessive redirect chain", async () => {
  const policy = { resolveAndValidate: async () => [{ address: "93.184.216.34", family: 4 as const }] };
  let count = 0;
  const transport = { request: async () => response(302, `https://example.com/hop-${++count}`) };
  await expect(new UrlHttpProbe(policy, transport).observe(new URL("https://example.com/"))).rejects.toThrow("redirect_limit_exceeded");
  expect(count).toBe(6);
});
