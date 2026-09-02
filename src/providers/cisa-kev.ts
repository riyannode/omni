import type { Evidence } from "../domain/risk.ts";
import { CachedLoader } from "../data/cache.ts";
import { UpstreamHttp } from "./http.ts";

type KevFeed = { vulnerabilities: Array<{ cveID: string; dateAdded?: string }>; catalogVersion?: string };

export const DEFAULT_KEV_FEED_URLS = [
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateFeed(feed: unknown): KevFeed {
  if (!isRecord(feed)) throw new Error("kev_feed_malformed");
  const vulnerabilities = feed.vulnerabilities;
  if ((feed.catalogVersion !== undefined && typeof feed.catalogVersion !== "string") || !Array.isArray(vulnerabilities) || vulnerabilities.some(vulnerability => {
    if (!isRecord(vulnerability) || typeof vulnerability.cveID !== "string" || vulnerability.cveID.length === 0) return true;
    return vulnerability.dateAdded !== undefined && typeof vulnerability.dateAdded !== "string";
  })) throw new Error("kev_feed_malformed");
  return feed as unknown as KevFeed;
}

function validateCachedFeed(value: unknown): { feed: KevFeed; feedUrl: string } {
  if (!isRecord(value) || !isRecord(value.value) || !isRecord(value.value.feed) || typeof value.value.feedUrl !== "string" || value.value.feedUrl.length === 0 || typeof value.cachedAt !== "string" || typeof value.expiresAt !== "string") throw new Error("kev_cache_malformed");
  try { new URL(value.value.feedUrl); } catch { throw new Error("kev_cache_malformed"); }
  const cachedAt = Date.parse(value.cachedAt); const expiresAt = Date.parse(value.expiresAt);
  if (!Number.isFinite(cachedAt) || !Number.isFinite(expiresAt) || expiresAt <= cachedAt) throw new Error("kev_cache_malformed");
  return { feed: validateFeed(value.value.feed), feedUrl: value.value.feedUrl };
}

export class CisaKevProvider {
  private readonly feedUrls: string[];
  private readonly cacheKey: string;

  constructor(
    private readonly cache: CachedLoader,
    private readonly http: UpstreamHttp,
    feedUrls: readonly string[] = DEFAULT_KEV_FEED_URLS
  ) {
    if (feedUrls.length === 0) throw new Error("CisaKevProvider requires at least one KEV feed URL");
    this.feedUrls = [...feedUrls];
    this.cacheKey = `feed:cisa-kev:${this.feedUrls.map(url => `${url.length}:${url}`).join("|")}`;
  }

  private async load(): Promise<{ feed: KevFeed; feedUrl: string }> {
    const failures: string[] = [];
    for (const feedUrl of this.feedUrls) {
      try {
        return { feed: validateFeed(await this.http.json<KevFeed>(feedUrl)), feedUrl };
      } catch (error) {
        failures.push(`${new URL(feedUrl).host}: ${error instanceof Error ? error.message : "unknown error"}`);
      }
    }
    throw new Error(`all KEV feeds unavailable (${failures.join("; ")})`);
  }

  async mark(ids: string[]): Promise<{ exploited: Set<string>; evidence: Evidence }> {
    const cached = await this.cache.getOrLoadWithMetadata<{ feed: KevFeed; feedUrl: string }>(
      this.cacheKey, 300, () => this.load()
    );
    const { feed, feedUrl } = validateCachedFeed(cached);
    const wanted = new Set(ids);
    const exploited = new Set((feed.vulnerabilities ?? []).map(v => v.cveID).filter(id => wanted.has(id)));
    return {
      exploited,
      evidence: {
        source: "CISA KEV",
        kind: "known_exploitation",
        observedAt: new Date().toISOString(),
        detail: {
          matched: [...exploited],
          feedUrl,
          ...(feed.catalogVersion === undefined ? {} : { catalogVersion: feed.catalogVersion }),
          catalogSize: (feed.vulnerabilities ?? []).length
        }
      }
    };
  }
}
