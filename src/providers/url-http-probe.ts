import type { UrlHttpObservation } from "../domain/url-risk.ts";
import type { ResolvedPublicAddress, PublicNetworkPolicy } from "./public-network.ts";
import type { PinnedHttpsResponse, PinnedHttpsTransport } from "./pinned-https.ts";

export const URL_HTTP_MAX_REDIRECTS = 5;
export const URL_HTTP_MAX_BODY_BYTES = 8192;
const URL_HTTP_REQUEST_POLICY = { method: "GET", tlsMode: "strict", maximumBodyBytes: URL_HTTP_MAX_BODY_BYTES, headers: { "user-agent": "OMNI/0.2 url-risk", accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.1", range: `bytes=0-${URL_HTTP_MAX_BODY_BYTES - 1}` } } as const;

type NetworkPolicy = Pick<PublicNetworkPolicy, "resolveAndValidate">;
type Transport = Pick<PinnedHttpsTransport, "request">;

function isRedirect(statusCode: number): boolean { return [301, 302, 303, 307, 308].includes(statusCode); }
function header(response: PinnedHttpsResponse, name: string): boolean { return response.headers.has(name); }

export class UrlHttpProbe {
  constructor(private readonly policy: NetworkPolicy, private readonly transport: Transport) {}

  async observe(start: URL): Promise<UrlHttpObservation> {
    let current = new URL(start.toString());
    current.hash = "";
    const redirects: UrlHttpObservation["redirects"] = [];
    for (let hop = 0; hop <= URL_HTTP_MAX_REDIRECTS; hop += 1) {
      if (current.protocol !== "https:" || current.username || current.password) throw new Error("invalid redirect target");
      const addresses = await this.policy.resolveAndValidate(current.hostname);
      const address = addresses[0];
      if (!address) throw new Error("disallowed network target");
      const response = await this.transport.request(current, address, URL_HTTP_REQUEST_POLICY);
      const location = response.headers.get("location");
      if (isRedirect(response.statusCode) && location !== null) {
        const next = new URL(location, current);
        next.hash = "";
        redirects.push({ from: current.toString(), to: next.toString(), statusCode: response.statusCode });
        if (next.protocol !== "https:") {
          return {
            status: "blocked",
            redirects,
            httpsDowngradeBlocked: true,
            securityHeaders: {}
          };
        }
        if (next.username || next.password) throw new Error("redirect credentials rejected");
        if (hop === URL_HTTP_MAX_REDIRECTS) throw new Error("redirect_limit_exceeded");
        current = next;
        continue;
      }
      const contentType = response.headers.get("content-type");
      return {
        status: "observed",
        statusCode: response.statusCode,
        ...(contentType === null ? {} : { contentType }),
        finalUrl: current.toString(),
        redirects,
        securityHeaders: {
          hsts: header(response, "strict-transport-security"),
          contentSecurityPolicy: header(response, "content-security-policy"),
          xContentTypeOptions: header(response, "x-content-type-options")
        }
      };
    }
    throw new Error("redirect_limit_exceeded");
  }
}
