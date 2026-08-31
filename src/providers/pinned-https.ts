import https from "node:https";
import type { LookupFunction } from "node:net";
import tls, { checkServerIdentity, type PeerCertificate, type TLSSocket } from "node:tls";
import type { ResolvedPublicAddress } from "./public-network.ts";

export type PinnedRequestOptions = {
  hostname: string;
  servername: string;
  address: string;
  port: number;
  path: string;
  method: "GET" | "HEAD";
  timeoutMs: number;
  maximumBodyBytes: number;
  headers: Record<string, string>;
};

export type PinnedHttpsResponse = {
  statusCode: number;
  headers: Headers;
  body: Uint8Array;
  tls: { authorized: boolean; hostnameMatch: boolean; validFrom?: string; validTo?: string; issuer?: string };
};
export type PinnedRequestExecutor = (options: PinnedRequestOptions) => Promise<PinnedHttpsResponse>;
function hostForTls(hostname: string): string { return hostname.replace(/^\[/, "").replace(/\]$/, ""); }

function certificateInfo(socket: TLSSocket, hostname: string): PinnedHttpsResponse["tls"] {
  const certificate = socket.getPeerCertificate() as PeerCertificate;
  const identityError = checkServerIdentity(hostForTls(hostname), certificate);
  const issuer = typeof certificate.issuer === "object" && certificate.issuer !== null ? String(certificate.issuer.CN ?? certificate.issuer.O ?? "") : undefined;
  return { authorized: socket.authorized, hostnameMatch: identityError === undefined, ...(certificate.valid_from ? { validFrom: certificate.valid_from } : {}), ...(certificate.valid_to ? { validTo: certificate.valid_to } : {}), ...(issuer ? { issuer } : {}) };
}

function pinnedLookup(address: string): LookupFunction {
  return (_hostname, lookupOptions, callback) => {
    const family = address.includes(":") ? 6 : 4;
    if (lookupOptions.all) callback(null, [{ address, family }]);
    else callback(null, address, family);
  };
}

async function inspectTls(options: PinnedRequestOptions): Promise<PinnedHttpsResponse["tls"]> {
  return await new Promise((resolve, reject) => {
    const socket = tls.connect({ host: options.hostname, servername: options.servername, port: options.port, lookup: pinnedLookup(options.address), rejectUnauthorized: false });
    socket.setTimeout(options.timeoutMs, () => socket.destroy(new Error("url probe timeout")));
    socket.once("secureConnect", () => { resolve(certificateInfo(socket, options.hostname)); socket.end(); });
    socket.once("error", reject);
  });
}

const defaultExecutor: PinnedRequestExecutor = async options => {
  const tlsInfo = await inspectTls(options);
  return await new Promise((resolve, reject) => {
    let settled = false;
    const request = https.request({ protocol: "https:", hostname: options.hostname, servername: options.servername, port: options.port, path: options.path, method: options.method, rejectUnauthorized: false, headers: options.headers, lookup: pinnedLookup(options.address) }, response => {
      const chunks: Uint8Array[] = [];
      let bytes = 0;
      response.on("data", chunk => {
        const value = chunk instanceof Uint8Array ? chunk : Buffer.from(chunk);
        bytes += value.byteLength;
        if (bytes > options.maximumBodyBytes) { response.destroy(new Error("url_response_oversized")); return; }
        chunks.push(value);
      });
      response.once("error", error => { if (!settled) { settled = true; reject(error); } });
      response.on("end", () => {
        if (settled) return;
        settled = true;
        const body = new Uint8Array(bytes);
        let offset = 0;
        for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
        resolve({ statusCode: response.statusCode ?? 0, headers: new Headers(Object.entries(response.headers).flatMap(([key, value]) => typeof value === "string" ? [[key, value] as const] : Array.isArray(value) ? [[key, value.join(", ")] as const] : [])), body, tls: tlsInfo });
      });
    });
    request.setTimeout(options.timeoutMs, () => request.destroy(new Error("url probe timeout")));
    request.once("error", error => { if (!settled) { settled = true; reject(error); } });
    request.end();
  });
};

export class PinnedHttpsTransport {
  constructor(private readonly timeoutMs: number, private readonly executor: PinnedRequestExecutor = defaultExecutor) {}

  async request(url: URL, address: ResolvedPublicAddress, maximumBodyBytes: number, method: "GET" | "HEAD" = "GET"): Promise<PinnedHttpsResponse> {
    if (!Number.isSafeInteger(maximumBodyBytes) || maximumBodyBytes < 1) throw new Error("url_response_limit_invalid");
    const result = await this.executor({ hostname: hostForTls(url.hostname), servername: hostForTls(url.hostname), address: address.address, port: Number(url.port || 443), path: `${url.pathname}${url.search}` || "/", method, timeoutMs: this.timeoutMs, maximumBodyBytes, headers: { host: url.host, "user-agent": "OMNI/0.2 url-risk", accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.1", range: `bytes=0-${maximumBodyBytes - 1}` } });
    if (result.body.byteLength > maximumBodyBytes) throw new Error("url_response_oversized");
    return result;
  }
}
