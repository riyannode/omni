import type { UrlThreatIntelStore } from "../data/threat-intel.ts";
import { UrlRiskEngine } from "../domain/url-risk-engine.ts";
import { normalizeUrlRiskTarget, type UrlRiskAssessment, type UrlRiskSnapshot } from "../domain/url-risk.ts";
import { createUrlRiskAdapters, type UrlRiskEvidenceAdapters } from "../providers/url-risk-evidence.ts";
import { PublicNetworkPolicy } from "../providers/public-network.ts";
import { UpstreamHttp } from "../providers/http.ts";

function message(error: unknown): string { return error instanceof Error ? error.message : "unknown error"; }
function evidence(source: string, kind: string, detail: Record<string, unknown>) {
  return { source, kind, observedAt: new Date().toISOString(), detail };
}

export class UrlRiskService {
  private readonly adapters: UrlRiskEvidenceAdapters;
  private readonly engine: UrlRiskEngine;

  constructor(
    threatIntel: UrlThreatIntelStore,
    http: UpstreamHttp,
    network = new PublicNetworkPolicy(undefined, http.getAdmission()),
    engine = new UrlRiskEngine(),
    adapters?: UrlRiskEvidenceAdapters
  ) {
    this.adapters = adapters ?? createUrlRiskAdapters(http, network, threatIntel);
    this.engine = engine;
  }

  async assess(rawUrl: string): Promise<UrlRiskAssessment> {
    const target = normalizeUrlRiskTarget(rawUrl);
    const snapshot: UrlRiskSnapshot = {
      subject: { type: "url", id: target.url },
      url: target.url,
      hostname: target.hostname,
      threatIntelChecked: false,
      threatFindings: [],
      evidence: [],
      sourceErrors: []
    };

    const [threatResult, rdapResult, dnsResult] = await Promise.allSettled([
      this.adapters.threatIntel.lookupUrl(target.url, target.hostname),
      this.adapters.rdap.observe(target.hostname),
      this.adapters.dns.observe(target.hostname)
    ]);
    if (threatResult.status === "fulfilled") {
      snapshot.threatIntelChecked = threatResult.value.checked;
      snapshot.threatFindings = threatResult.value.findings;
      if (!threatResult.value.checked) snapshot.sourceErrors.push("Threat intelligence: no active URL/hostname feed configured");
      else {
        const findingSources = [...new Set(snapshot.threatFindings.map(finding => finding.source))].sort();
        snapshot.evidence.push(evidence("OMNI threat intelligence", "url_ioc_lookup", { configuredCapability: "url_and_hostname", url: target.url, hostname: target.hostname, matches: snapshot.threatFindings.length, findingSources }));
      }
    } else snapshot.sourceErrors.push(`Threat intelligence: ${message(threatResult.reason)}`);
    if (rdapResult.status === "fulfilled") {
      snapshot.rdap = rdapResult.value;
      snapshot.evidence.push(evidence("RDAP", "registration", rdapResult.value as unknown as Record<string, unknown>));
    } else snapshot.sourceErrors.push(`RDAP: ${message(rdapResult.reason)}`);
    if (dnsResult.status === "fulfilled") {
      snapshot.dns = { addresses: dnsResult.value.addresses, cname: dnsResult.value.cname };
      snapshot.evidence.push(evidence("DNS", "resolution", dnsResult.value as unknown as Record<string, unknown>));
    } else snapshot.sourceErrors.push(`DNS: ${message(dnsResult.reason)}`);

    const publicAddresses = snapshot.dns?.addresses.filter(address => address.classification === "public").map(({ address, family }) => ({ address, family })) ?? [];
    const hasDisallowed = snapshot.dns?.addresses.some(address => address.classification !== "public") ?? false;
    if (publicAddresses.length > 0 && !hasDisallowed) {
      const [tlsResult, httpResult] = await Promise.allSettled([
        this.adapters.tls.observe(new URL(target.url), publicAddresses),
        this.adapters.http.observe(new URL(target.url))
      ]);
      if (tlsResult.status === "fulfilled") { snapshot.tls = tlsResult.value; snapshot.evidence.push(evidence("TLS", "certificate", tlsResult.value as unknown as Record<string, unknown>)); }
      else snapshot.sourceErrors.push(`TLS: ${message(tlsResult.reason)}`);
      if (httpResult.status === "fulfilled") { snapshot.http = httpResult.value; snapshot.evidence.push(evidence("HTTP probe", "metadata", httpResult.value as unknown as Record<string, unknown>)); }
      else snapshot.sourceErrors.push(`HTTP probe: ${message(httpResult.reason)}`);
    } else {
      snapshot.sourceErrors.push(`TLS: ${hasDisallowed ? "disallowed network target" : "DNS did not provide a public address"}`);
      snapshot.sourceErrors.push(`HTTP probe: ${hasDisallowed ? "disallowed network target" : "DNS did not provide a public address"}`);
    }

    return this.engine.assess(snapshot);
  }
}
