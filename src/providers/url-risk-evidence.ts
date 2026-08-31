import { resolveCname } from "node:dns/promises";
import type { UrlThreatIntelStore } from "../data/threat-intel.ts";
import type { UrlDnsObservation, UrlRdapObservation, UrlTlsObservation } from "../domain/url-risk.ts";
import { UpstreamHttp } from "./http.ts";
import { PublicNetworkPolicy, type ClassifiedNetworkAddress, type ResolvedPublicAddress } from "./public-network.ts";
import { PinnedHttpsTransport } from "./pinned-https.ts";
import { UrlHttpProbe } from "./url-http-probe.ts";

export type UrlRiskEvidenceAdapters = {
  threatIntel: UrlThreatIntelStore;
  dns: Pick<UrlDnsProvider, "observe">;
  rdap: Pick<RdapProvider, "observe">;
  tls: Pick<TlsProvider, "observe">;
  http: Pick<UrlHttpProbe, "observe">;
};

export class UrlDnsProvider {
  constructor(private readonly policy: PublicNetworkPolicy, private readonly admission: import("./http.ts").UpstreamAdmission) {}
  async observe(hostname: string): Promise<UrlDnsObservation> {
    const addresses: ClassifiedNetworkAddress[] = await this.policy.resolveAndClassify(hostname);
    let cname: string[] = [];
    try { cname = (await this.admission.run(() => resolveCname(hostname))).map(item => item.toLowerCase()).sort(); } catch {}
    return { addresses, cname };
  }
}

type RdapResponse = {
  handle?: string;
  ldhName?: string;
  entities?: Array<{ roles?: string[]; vcardArray?: [string, Array<Array<unknown>>] }>;
  events?: Array<{ eventAction?: string; eventDate?: string }>;
};

export class RdapProvider {
  constructor(private readonly transport: Pick<PinnedHttpsTransport, "request">, private readonly policy: PublicNetworkPolicy) {}

  async observe(hostname: string): Promise<UrlRdapObservation> {
    let current = new URL(`https://rdap.org/domain/${encodeURIComponent(hostname)}`);
    for (let hop = 0; hop <= 2; hop += 1) {
      if (current.protocol !== "https:" || current.username || current.password) throw new Error("invalid RDAP redirect target");
      const address = (await this.policy.resolveAndValidate(current.hostname))[0];
      if (!address) throw new Error("RDAP host did not resolve");
      const response = await this.transport.request(current, address, { method: "GET", tlsMode: "strict", responseBodyMode: "bounded", maximumBodyBytes: 64 * 1024, headers: { "user-agent": "OMNI/0.2 rdap", accept: "application/rdap+json,application/json;q=0.8" } });
      const location = response.headers.get("location");
      if (response.statusCode >= 300 && response.statusCode < 400 && location !== null) {
        if (hop === 2) throw new Error("RDAP redirect limit exceeded");
        const next = new URL(location, current);
        next.hash = "";
        current = next;
        continue;
      }
      if (response.statusCode === 404) return { status: "not_found" };
      if (response.statusCode < 200 || response.statusCode >= 300) throw new Error(`RDAP upstream HTTP ${response.statusCode}`);
      const data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(response.body)) as RdapResponse;
      const events = (data.events ?? []).flatMap(event => event.eventAction && event.eventDate ? [{ eventAction: event.eventAction, eventDate: event.eventDate }] : []).sort((left, right) => left.eventAction.localeCompare(right.eventAction) || left.eventDate.localeCompare(right.eventDate));
      const registrar = data.entities?.flatMap(entity => entity.roles?.includes("registrar") ? (entity.vcardArray?.[1] ?? []) : []).flatMap(item => item.length > 3 && typeof item[3] === "string" ? [item[3]] : [])[0];
      return { status: "registered", ...(data.handle ? { handle: data.handle } : {}), ...(data.ldhName ? { ldhName: data.ldhName } : {}), ...(registrar ? { registrar } : {}), ...(events.length ? { events } : {}) };
    }
    throw new Error("RDAP redirect limit exceeded");
  }
}

export class TlsProvider {
  constructor(private readonly transport: Pick<PinnedHttpsTransport, "request">) {}
  async observe(url: URL, addresses: ResolvedPublicAddress[]): Promise<UrlTlsObservation> {
    const address = addresses[0];
    if (!address) throw new Error("TLS requires a validated public address");
    const response = await this.transport.request(url, address, { method: "HEAD", tlsMode: "observe", responseBodyMode: "bounded", maximumBodyBytes: 1024, headers: { "user-agent": "OMNI/0.2 url-risk-tls", accept: "*/*" } });
    return { status: response.tls.authorized && response.tls.hostnameMatch ? "valid" : "invalid", authorized: response.tls.authorized, hostnameMatch: response.tls.hostnameMatch, ...(response.tls.validFrom ? { validFrom: response.tls.validFrom } : {}), ...(response.tls.validTo ? { validTo: response.tls.validTo } : {}), ...(response.tls.issuer ? { issuer: response.tls.issuer } : {}) };
  }
}

export function createUrlRiskAdapters(http: UpstreamHttp, policy: PublicNetworkPolicy | undefined, threatIntel: UrlThreatIntelStore): UrlRiskEvidenceAdapters {
  const network = policy ?? new PublicNetworkPolicy(undefined, http.getAdmission());
  const transport = new PinnedHttpsTransport(http.getTimeoutMs(), undefined, http.getAdmission());
  return { threatIntel, dns: new UrlDnsProvider(network, http.getAdmission()), rdap: new RdapProvider(transport, network), tls: new TlsProvider(transport), http: new UrlHttpProbe(network, transport) };
}
