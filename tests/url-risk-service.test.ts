import { describe, expect, test } from "bun:test";
import { UrlRiskService } from "../src/services/url-risk.ts";
import type { UrlRiskEvidenceAdapters } from "../src/providers/url-risk-evidence.ts";
import type { UrlThreatIntelStore } from "../src/data/threat-intel.ts";
import { UpstreamHttp } from "../src/providers/http.ts";

const publicAddress = { address: "93.184.216.34", family: 4 as const, classification: "public" as const };
function adapters(overrides: Partial<UrlRiskEvidenceAdapters> = {}): UrlRiskEvidenceAdapters {
  return {
    threatIntel: { async lookupUrl() { return { checked: true, findings: [] }; } },
    dns: { async observe() { return { addresses: [publicAddress], cname: [] }; } } as UrlRiskEvidenceAdapters["dns"],
    rdap: { async observe() { return { status: "registered", ldhName: "example.com" }; } } as UrlRiskEvidenceAdapters["rdap"],
    tls: { async observe() { return { status: "valid", authorized: true, hostnameMatch: true }; } } as UrlRiskEvidenceAdapters["tls"],
    http: { async observe() { return { status: "observed", statusCode: 200, finalUrl: "https://example.com/", redirects: [], securityHeaders: { hsts: true, contentSecurityPolicy: true, xContentTypeOptions: true } }; } } as UrlRiskEvidenceAdapters["http"],
    ...overrides
  };
}

const noOpThreatIntel: UrlThreatIntelStore = { async lookupUrl() { return { checked: true, findings: [] }; } };
const http = new UpstreamHttp(1000, 8, 8);

describe("UrlRiskService", () => {
  test("returns normalized URL subject and vendor-neutral lookup evidence", async () => {
    const service = new UrlRiskService(noOpThreatIntel, http, undefined, undefined, adapters({
      threatIntel: { async lookupUrl() { return { checked: true, findings: [{ indicatorType: "hostname", indicator: "example.com", threatType: "phishing", severity: "critical", source: "another-licensed-feed" }] }; } }
    }));
    const result = await service.assess("HTTPS://Example.COM/#fragment");
    expect(result.subject).toEqual({ type: "url", id: "https://example.com/" });
    expect(result.evidence[0]).toMatchObject({ source: "OMNI threat intelligence", kind: "url_ioc_lookup" });
    expect(result.evidence[0]?.detail).toMatchObject({ findingSources: ["another-licensed-feed"] });
    expect(result.evidence.map(item => item.source)).toEqual(["OMNI threat intelligence", "RDAP", "DNS", "TLS", "HTTP probe"]);
    expect(result.recommendation).toBe("do_not_proceed");
  });

  test("reports an unconfigured URL threat capability without naming Phishing.Database", async () => {
    const service = new UrlRiskService(noOpThreatIntel, http, undefined, undefined, adapters({
      threatIntel: { async lookupUrl() { return { checked: false, findings: [] }; } }
    }));
    const result = await service.assess("https://example.com/");
    expect(result.sourceErrors).toContain("Threat intelligence: no active URL/hostname feed configured");
    expect(result.sourceErrors.some(item => item.includes("Phishing.Database"))).toBe(false);
  });

  test("does not connect to TLS or HTTP when DNS classifies a target as disallowed", async () => {
    let tlsCalls = 0;
    let httpCalls = 0;
    const service = new UrlRiskService(noOpThreatIntel, http, undefined, undefined, adapters({
      dns: { async observe() { return { addresses: [{ address: "169.254.169.254", family: 4, classification: "link_local" }], cname: [] }; } } as UrlRiskEvidenceAdapters["dns"],
      tls: { async observe() { tlsCalls += 1; return { status: "valid" }; } } as UrlRiskEvidenceAdapters["tls"],
      http: { async observe() { httpCalls += 1; return { status: "observed", redirects: [], securityHeaders: {} }; } } as UrlRiskEvidenceAdapters["http"]
    }));
    const result = await service.assess("https://metadata.example/");
    expect(tlsCalls).toBe(0);
    expect(httpCalls).toBe(0);
    expect(result.urlDimensions.networkBehavior).toBe("critical");
    expect(result.signals.some(signal => signal.code === "DISALLOWED_NETWORK_ADDRESS")).toBe(true);
  });
});
