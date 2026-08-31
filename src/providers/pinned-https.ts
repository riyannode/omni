import https from "node:https";
import type { LookupFunction } from "node:net";
import tls, { checkServerIdentity, type PeerCertificate, type TLSSocket } from "node:tls";
import type { ResolvedPublicAddress } from "./public-network.ts";
import { UpstreamAdmission } from "./http.ts";

export type PinnedTlsMode = "strict" | "observe";
export type ResponseBodyMode = "discard" | "bounded";
export type PinnedRequestPolicy = {
  method: "GET" | "HEAD";
  tlsMode: PinnedTlsMode;
  responseBodyMode: ResponseBodyMode;
  maximumBodyBytes: number;
  headers: Record<string, string>;
};
export type PinnedRequestOptions = PinnedRequestPolicy & {
  hostname: string;
  servername: string;
  address: string;
  port: number;
  path: string;
  timeoutMs: number;
  deadlineAt: number;
  signal: AbortSignal;
};
export type PinnedHttpsResponse = {
  statusCode: number;
  headers: Headers;
  body: Uint8Array;
  tls: { authorized: boolean; hostnameMatch: boolean; validFrom?: string; validTo?: string; issuer?: string };
};
export type PinnedRequestExecutor = (options: PinnedRequestOptions) => Promise<PinnedHttpsResponse>;

function hostForTls(hostname: string): string { return hostname.replace(/^\[/, "").replace(/\]$/, ""); }
function responseHeaders(response: import("node:http").IncomingMessage): Headers {
  return new Headers(Object.entries(response.headers).flatMap(([key, value]) => typeof value === "string" ? [[key, value] as const] : Array.isArray(value) ? [[key, value.join(", ")] as const] : []));
}
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
function deadlineError(): Error { return new Error("url_probe_deadline_exceeded"); }
function abortError(signal: AbortSignal): Error { return signal.reason instanceof Error ? signal.reason : deadlineError(); }

async function inspectTls(options: PinnedRequestOptions): Promise<PinnedHttpsResponse["tls"]> {
  return await new Promise((resolve, reject) => {
    const remaining = options.deadlineAt - Date.now();
    if (remaining <= 0) { reject(deadlineError()); return; }
    let settled = false;
    const socket = tls.connect({ host: options.hostname, servername: options.servername, port: options.port, lookup: pinnedLookup(options.address), rejectUnauthorized: options.tlsMode === "strict" });
    const absolute = setTimeout(() => socket.destroy(deadlineError()), remaining);
    const abort = () => socket.destroy(abortError(options.signal));
    if (options.signal.aborted) { abort(); return; }
    options.signal.addEventListener("abort", abort, { once: true });
    const finishResolve = (value: PinnedHttpsResponse["tls"]) => {
      if (settled) return;
      settled = true;
      clearTimeout(absolute);
      options.signal.removeEventListener("abort", abort);
      resolve(value);
    };
    const finishReject = (error: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(absolute);
      options.signal.removeEventListener("abort", abort);
      reject(error);
    };
    socket.setTimeout(Math.min(options.timeoutMs, remaining), () => socket.destroy(new Error("url probe timeout")));
    socket.once("secureConnect", () => { finishResolve(certificateInfo(socket, options.hostname)); socket.end(); });
    socket.once("error", error => finishReject(error));
  });
}

const defaultExecutor: PinnedRequestExecutor = async options => {
  const tlsInfo = await inspectTls(options);
  return await new Promise((resolve, reject) => {
    const remaining = options.deadlineAt - Date.now();
    if (remaining <= 0) { reject(deadlineError()); return; }
    let settled = false;
    let abort: () => void;
    const request = https.request({ protocol: "https:", hostname: options.hostname, servername: options.servername, port: options.port, path: options.path, method: options.method, rejectUnauthorized: options.tlsMode === "strict", headers: options.headers, lookup: pinnedLookup(options.address) }, response => {
      const headers = responseHeaders(response);
      if (options.responseBodyMode === "discard") {
        settled = true;
        clearTimeout(absolute);
        options.signal.removeEventListener("abort", abort);
        resolve({ statusCode: response.statusCode ?? 0, headers, body: new Uint8Array(), tls: tlsInfo });
        response.destroy();
        return;
      }
      const chunks: Uint8Array[] = [];
      let bytes = 0;
      response.on("data", chunk => {
        const value = chunk instanceof Uint8Array ? chunk : Buffer.from(chunk);
        bytes += value.byteLength;
        if (bytes > options.maximumBodyBytes) { response.destroy(new Error("url_response_oversized")); return; }
        chunks.push(value);
      });
      response.once("error", error => { if (!settled) { settled = true; clearTimeout(absolute); options.signal.removeEventListener("abort", abort); reject(error); } });
      response.on("end", () => {
        if (settled) return;
        settled = true;
        clearTimeout(absolute);
        options.signal.removeEventListener("abort", abort);
        const body = new Uint8Array(bytes);
        let offset = 0;
        for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
        resolve({ statusCode: response.statusCode ?? 0, headers, body, tls: tlsInfo });
      });
    });
    const absolute = setTimeout(() => request.destroy(deadlineError()), remaining);
    abort = () => request.destroy(abortError(options.signal));
    if (options.signal.aborted) { abort(); return; }
    options.signal.addEventListener("abort", abort, { once: true });
    request.setTimeout(Math.min(options.timeoutMs, remaining), () => request.destroy(new Error("url probe timeout")));
    request.once("error", error => { if (!settled) { settled = true; clearTimeout(absolute); options.signal.removeEventListener("abort", abort); reject(error); } });
    request.end();
  });
};

export class PinnedHttpsTransport {
  constructor(private readonly timeoutMs: number, private readonly executor: PinnedRequestExecutor = defaultExecutor, private readonly admission = new UpstreamAdmission(1, 0)) {}

  async request(url: URL, address: ResolvedPublicAddress, policy: PinnedRequestPolicy): Promise<PinnedHttpsResponse> {
    if (url.protocol !== "https:") throw new Error("https_required");
    if (!Number.isSafeInteger(policy.maximumBodyBytes) || policy.maximumBodyBytes < 1) throw new Error("url_response_limit_invalid");
    return await this.admission.run(async () => {
      const controller = new AbortController();
      const options: PinnedRequestOptions = {
        ...policy,
        hostname: hostForTls(url.hostname),
        servername: hostForTls(url.hostname),
        address: address.address,
        port: Number(url.port || 443),
        path: `${url.pathname}${url.search}` || "/",
        timeoutMs: this.timeoutMs,
        deadlineAt: Date.now() + this.timeoutMs,
        signal: controller.signal,
        headers: { ...policy.headers, host: url.host }
      };
      let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<never>((_, reject) => { deadlineTimer = setTimeout(() => reject(deadlineError()), this.timeoutMs); });
      const operation = this.executor(options);
      try {
        const result = await Promise.race([operation, deadline]);
        if (policy.responseBodyMode === "bounded" && result.body.byteLength > policy.maximumBodyBytes) throw new Error("url_response_oversized");
        return result;
      } catch (error) {
        controller.abort(error instanceof Error ? error : deadlineError());
        try { await operation; } catch {}
        throw error;
      } finally {
        if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
      }
    });
  }
}
