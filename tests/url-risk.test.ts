import { describe, expect, test } from "bun:test";
import { UrlRiskEngine } from "../src/domain/url-risk-engine.ts";
import type { UrlRiskSnapshot } from "../src/domain/url-risk.ts";
import { PinnedHttpsTransport } from "../src/providers/pinned-https.ts";
import { PublicNetworkPolicy } from "../src/providers/public-network.ts";
import { UrlHttpProbe } from "../src/providers/url-http-probe.ts";
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
});

describe("PublicNetworkPolicy", () => {
  test("rejects every resolved address when any candidate is not globally routable", async () => {
    const policy = new PublicNetworkPolicy(async () => [{ address: "93.184.216.34", family: 4 }, { address: "169.254.169.254", family: 4 }]);
    await expect(policy.resolveAndValidate("example.com")).rejects.toThrow("disallowed");
  });

  test("rejects localhost, loopback, RFC1918, link-local, metadata, multicast, and reserved IPv4", async () => {
    for (const address of ["localhost", "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.1.1", "169.254.169.254", "224.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1"]) {
      await expect(new PublicNetworkPolicy().resolveAndValidate(address)).rejects.toThrow("disallowed");
    }
  });

  test("rejects IPv6 loopback, unique-local, link-local, multicast, unspecified, documentation, and mapped addresses", async () => {
    for (const address of ["::1", "fc00::1", "fe80::1", "ff02::1", "::", "2001:db8::1", "::ffff:192.168.0.1"]) {
      const policy = new PublicNetworkPolicy(async () => [{ address, family: 6 }]);
      await expect(policy.resolveAndValidate("example.com")).rejects.toThrow("disallowed");
    }
  });
});

test("PinnedHttpsTransport connects to the validated address with original hostname identity", async () => {
  const calls: Array<{ hostname: string; servername: string; address: string; host: string }> = [];
  const transport = new PinnedHttpsTransport(1000, async options => {
    calls.push({ hostname: options.hostname, servername: options.servername, address: options.address, host: options.headers.host! });
    return { statusCode: 200, headers: new Headers({ "content-type": "text/plain" }), body: new Uint8Array(), tls: { authorized: true, hostnameMatch: true } };
  });
  await transport.request(new URL("https://example.com/path"), { address: "93.184.216.34", family: 4 }, 1024);
  expect(calls).toEqual([{ hostname: "example.com", servername: "example.com", address: "93.184.216.34", host: "example.com" }]);
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
