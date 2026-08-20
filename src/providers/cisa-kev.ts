import type { Evidence } from "../domain/risk.ts";
import { CachedLoader } from "../data/cache.ts";
import { UpstreamHttp } from "./http.ts";

type KevFeed = { vulnerabilities?: Array<{ cveID: string; dateAdded?: string }>; catalogVersion?: string };

export const DEFAULT_KEV_FEED_URLS = [
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
] as const;

export class CisaKevProvider {
  private readonly feedUrls: string[];

  constructor(
    private readonly cache: CachedLoader,
    private readonly http: UpstreamHttp,
    feedUrls: readonly string[] = DEFAULT_KEV_FEED_URLS
  ) {
    if (feedUrls.length === 0) throw new Error("CisaKevProvider requires at least one KEV feed URL");
    this.feedUrls = [...feedUrls];
  }

  private async load(): Promise<{ feed: KevFeed; feedUrl: string }> {
    const failures: string[] = [];
    for (const feedUrl of this.feedUrls) {
      try {
        return { feed: await this.http.json<KevFeed>(feedUrl), feedUrl };
      } catch (error) {
        failures.push(`${new URL(feedUrl).host}: ${error instanceof Error ? error.message : "unknown error"}`);
      }
    }
    throw new Error(`all KEV feeds unavailable (${failures.join("; ")})`);
  }

  async mark(ids: string[]): Promise<{ exploited: Set<string>; evidence: Evidence }> {
    const { feed, feedUrl } = await this.cache.getOrLoad<{ feed: KevFeed; feedUrl: string }>(
      "feed:cisa-kev", 300, () => this.load()
    );
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
