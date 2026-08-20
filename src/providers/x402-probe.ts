import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { Evidence } from "../domain/risk.ts";
import { UpstreamHttp } from "./http.ts";

function privateIpv4(ip: string): boolean {
  const [a, b] = ip.split(".").map(Number);
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b !== undefined && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b !== undefined && b >= 64 && b <= 127) return true;
  return false;
}

function privateIpv6(ip: string): boolean {
  const value = ip.toLowerCase();
  return value === "::1" || value === "::" || value.startsWith("fc") || value.startsWith("fd") || value.startsWith("fe8") || value.startsWith("fe9") || value.startsWith("fea") || value.startsWith("feb");
}

export class X402Probe {
  constructor(private readonly http: UpstreamHttp, private readonly allowedHosts: Set<string>) {}

  private async assertPublic(url: URL, circleListed: boolean): Promise<void> {
    if (url.protocol !== "https:") throw new Error("endpoint probe requires https");
    const host = url.hostname.toLowerCase();
    if (!circleListed && !this.allowedHosts.has(host)) throw new Error("unlisted endpoint host not allowlisted");

    if (isIP(host)) {
      if (privateIpv4(host) || privateIpv6(host)) throw new Error("private endpoint address rejected");
      return;
    }

    const addresses = await lookup(host, { all: true });
    if (addresses.length === 0) throw new Error("endpoint host did not resolve");
    for (const { address } of addresses) {
      if (privateIpv4(address) || privateIpv6(address)) throw new Error("endpoint resolves to private address");
    }
  }

  async unpaidGet(resource: string, circleListed: boolean): Promise<{ status: number; paymentOptions: number; evidence: Evidence }> {
    const url = new URL(resource);
    await this.assertPublic(url, circleListed);
    const response = await this.http.request(url, {
      method: "GET",
      redirect: "manual",
      headers: { "user-agent": "OMNI/0.2 x402-preflight" }
    });
    const raw = response.headers.get("payment-required") ?? response.headers.get("PAYMENT-REQUIRED");
    let paymentOptions = 0;
    if (raw) {
      try {
        const parsed = JSON.parse(Buffer.from(raw, "base64").toString("utf8")) as { accepts?: unknown[] };
        paymentOptions = parsed.accepts?.length ?? 0;
      } catch {
        paymentOptions = 0;
      }
    }
    await response.body?.cancel();
    return {
      status: response.status,
      paymentOptions,
      evidence: {
        source: "OMNI active probe",
        kind: "unpaid_x402_handshake",
        observedAt: new Date().toISOString(),
        detail: { resource, status: response.status, paymentOptions }
      }
    };
  }
}
