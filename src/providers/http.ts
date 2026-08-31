type Waiter = () => void;

const USER_AGENT = "OMNI/0.2 (+https://github.com/omni; x402-risk-preflight)";

export class UpstreamHttpError extends Error {
  constructor(public readonly status: number, public readonly host: string) {
    super(`upstream ${status} ${host}`);
    this.name = "UpstreamHttpError";
  }
}

function withIdentity(init: RequestInit): RequestInit {
  const headers = new Headers(init.headers);
  if (!headers.has("user-agent")) headers.set("user-agent", USER_AGENT);
  if (!headers.has("accept")) headers.set("accept", "application/json");
  return { ...init, headers };
}

export class UpstreamHttp {
  private active = 0;
  private readonly waiters: Waiter[] = [];

  constructor(
    private readonly timeoutMs: number,
    private readonly maxInFlight: number,
    private readonly maxQueue: number
  ) {}

  async json<T>(url: string, init: RequestInit = {}): Promise<T> {
    await this.acquire();
    try {
      const response = await fetch(url, { ...withIdentity(init), signal: AbortSignal.timeout(this.timeoutMs) });
      if (!response.ok) throw new UpstreamHttpError(response.status, new URL(url).host);
      return await response.json() as T;
    } finally {
      this.release();
    }
  }

  async boundedJson<T>(url: string, maximumBytes: number, init: RequestInit = {}): Promise<T> {
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) throw new Error("upstream_response_limit_invalid");
    await this.acquire();
    try {
      const response = await fetch(url, { ...withIdentity(init), redirect: "error", signal: AbortSignal.timeout(this.timeoutMs) });
      if (!response.ok) throw new UpstreamHttpError(response.status, new URL(url).host);
      const length = response.headers.get("content-length");
      if (length !== null && Number(length) > maximumBytes) throw new Error("upstream_response_oversized");
      if (!response.body) throw new Error("upstream_response_missing_body");
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let bytes = 0;
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        bytes += chunk.value.byteLength;
        if (bytes > maximumBytes) {
          await reader.cancel();
          throw new Error("upstream_response_oversized");
        }
        chunks.push(chunk.value);
      }
      const body = new Uint8Array(bytes);
      let offset = 0;
      for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)) as T;
    } finally {
      this.release();
    }
  }

  async request(url: string | URL, init: RequestInit = {}): Promise<Response> {
    await this.acquire();
    try {
      return await fetch(url, { ...withIdentity(init), signal: AbortSignal.timeout(this.timeoutMs) });
    } finally {
      this.release();
    }
  }

  getTimeoutMs(): number { return this.timeoutMs; }

  private async acquire(): Promise<void> {
    if (this.active < this.maxInFlight) {
      this.active += 1;
      return;
    }
    if (this.waiters.length >= this.maxQueue) throw new Error("upstream capacity exhausted");
    await new Promise<void>(resolve => this.waiters.push(resolve));
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) {
      next();
      return;
    }
    this.active -= 1;
  }
}
