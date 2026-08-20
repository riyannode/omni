type Waiter = () => void;

const USER_AGENT = "OMNI/0.2 (+https://github.com/omni; x402-risk-preflight)";

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
      if (!response.ok) throw new Error(`upstream ${response.status} ${new URL(url).host}`);
      return await response.json() as T;
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
