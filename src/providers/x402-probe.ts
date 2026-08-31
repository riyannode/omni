import type { Evidence } from "../domain/risk.ts";
import { observePaymentOptions, type ObservedPaymentRequirement } from "../domain/x402-preflight-consistency.ts";
import { UpstreamHttp } from "./http.ts";
import { PublicNetworkPolicy } from "./public-network.ts";
import { PinnedHttpsTransport, type PinnedRequestPolicy } from "./pinned-https.ts";

export const X402_REQUEST_POLICY: PinnedRequestPolicy = { method: "GET", tlsMode: "strict", responseBodyMode: "discard", maximumBodyBytes: 8192, headers: { "user-agent": "OMNI/0.2 x402-preflight", accept: "application/json" } };

export class X402Probe {
  private readonly transport: PinnedHttpsTransport;
  constructor(http: UpstreamHttp, private readonly network = new PublicNetworkPolicy(undefined, http.getAdmission()), transport?: PinnedHttpsTransport) { this.transport = transport ?? new PinnedHttpsTransport(http.getTimeoutMs(), undefined, http.getAdmission()); }

  async unpaidGet(resource: string): Promise<{ status: number; paymentOptions: ObservedPaymentRequirement[]; evidence: Evidence }> {
    const url = new URL(resource);
    if (url.protocol !== "https:") throw new Error("https_required");
    const addresses = await this.network.resolveAndValidate(url.hostname);
    const address = addresses[0];
    if (!address) throw new Error("endpoint host did not resolve");
    const response = await this.transport.request(url, address, X402_REQUEST_POLICY);
    const raw = response.headers.get("payment-required") ?? response.headers.get("PAYMENT-REQUIRED");
    let paymentOptions: ObservedPaymentRequirement[] = [];
    if (raw) {
      try {
        const parsed = JSON.parse(Buffer.from(raw, "base64").toString("utf8")) as { accepts?: unknown };
        paymentOptions = observePaymentOptions(parsed.accepts);
      } catch {
        paymentOptions = [];
      }
    }
    return {
      status: response.statusCode,
      paymentOptions,
      evidence: {
        source: "OMNI active probe",
        kind: "unpaid_x402_handshake",
        observedAt: new Date().toISOString(),
        detail: { resource, status: response.statusCode, paymentOptions: paymentOptions.length }
      }
    };
  }
}
