import { RedisClient } from "bun";

export interface Cache {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
}

class MemoryCache implements Cache {
  private readonly entries = new Map<string, { value: string; expires: number }>();

  constructor(private readonly maxEntries = 10_000) {}

  async get(key: string): Promise<string | null> {
    const hit = this.entries.get(key);
    if (!hit) return null;
    if (hit.expires <= Date.now()) {
      this.entries.delete(key);
      return null;
    }
    this.entries.delete(key);
    this.entries.set(key, hit);
    return hit.value;
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    this.entries.delete(key);
    this.entries.set(key, { value, expires: Date.now() + ttlSeconds * 1000 });
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
  }
}

class ValkeyCache implements Cache {
  private readonly client: RedisClient;

  constructor(url: string) {
    this.client = new RedisClient(url, {
      connectionTimeout: 500,
      maxRetries: 1,
      enableOfflineQueue: false,
      enableAutoPipelining: true,
      autoReconnect: true
    });
  }

  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    await this.client.set(key, value, "EX", ttlSeconds);
  }
}

class TieredCache implements Cache {
  constructor(private readonly distributed: Cache, private readonly local: Cache) {}

  async get(key: string): Promise<string | null> {
    try {
      const value = await this.distributed.get(key);
      if (value !== null) return value;
    } catch {}
    return this.local.get(key);
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    await this.local.set(key, value, ttlSeconds);
    try {
      await this.distributed.set(key, value, ttlSeconds);
    } catch {}
  }
}

export class CachedLoader {
  private readonly inFlight = new Map<string, Promise<unknown>>();

  constructor(private readonly cache: Cache) {}

  async getOrLoad<T>(key: string, ttlSeconds: number, loader: () => Promise<T>): Promise<T> {
    const cached = await this.cache.get(key);
    if (cached !== null) {
      try {
        return JSON.parse(cached) as T;
      } catch {}
    }

    const existing = this.inFlight.get(key) as Promise<T> | undefined;
    if (existing) return existing;

    const pending = loader()
      .then(async value => {
        await this.cache.set(key, JSON.stringify(value), ttlSeconds);
        return value;
      })
      .finally(() => this.inFlight.delete(key));

    this.inFlight.set(key, pending);
    return pending;
  }
}

export function createCache(redisUrl?: string): Cache {
  const local = new MemoryCache();
  return redisUrl ? new TieredCache(new ValkeyCache(redisUrl), local) : local;
}
