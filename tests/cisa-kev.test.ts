import { describe, expect, test } from "bun:test";
import { CisaKevProvider, DEFAULT_KEV_FEED_URLS } from "../src/providers/cisa-kev.ts";
import { CachedLoader, type Cache } from "../src/data/cache.ts";
import type { UpstreamHttp } from "../src/providers/http.ts";

class NullCache implements Cache {
  async get(): Promise<string | null> { return null; }
  async set(): Promise<void> {}
}

function loader() {
  return new CachedLoader(new NullCache());
}

function httpStub(handler: (url: string) => Promise<unknown>): UpstreamHttp {
  return { json: (url: string) => handler(url) } as unknown as UpstreamHttp;
}

describe("CisaKevProvider", () => {
  test("keeps the official cisa.gov feed as the first source", () => {
    expect(DEFAULT_KEV_FEED_URLS[0]).toBe("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    expect(DEFAULT_KEV_FEED_URLS.length).toBeGreaterThan(1);
  });

  test("falls back to the next feed when the primary returns an upstream error", async () => {
    const attempted: string[] = [];
    const provider = new CisaKevProvider(loader(), httpStub(async url => {
      attempted.push(url);
      if (url.includes("www.cisa.gov")) throw new Error("upstream 403 www.cisa.gov");
      return { catalogVersion: "2026.08.19", vulnerabilities: [{ cveID: "CVE-2021-44228" }] };
    }));

    const result = await provider.mark(["CVE-2021-44228", "CVE-2000-0001"]);

    expect(attempted.length).toBe(2);
    expect([...result.exploited]).toEqual(["CVE-2021-44228"]);
    expect(result.evidence.detail.feedUrl).toBe(DEFAULT_KEV_FEED_URLS[1]);
    expect(result.evidence.detail.catalogVersion).toBe("2026.08.19");
  });

  test("does not silently claim exploitation evidence when every feed fails", async () => {
    const provider = new CisaKevProvider(loader(), httpStub(async () => { throw new Error("upstream 403"); }));
    await expect(provider.mark(["CVE-2021-44228"])).rejects.toThrow(/all KEV feeds unavailable/);
  });

  test("honours a configured feed override", async () => {
    const attempted: string[] = [];
    const provider = new CisaKevProvider(loader(), httpStub(async url => {
      attempted.push(url);
      return { vulnerabilities: [] };
    }), ["https://mirror.internal/kev.json"]);

    const result = await provider.mark(["CVE-2021-44228"]);

    expect(attempted).toEqual(["https://mirror.internal/kev.json"]);
    expect(result.evidence.detail.feedUrl).toBe("https://mirror.internal/kev.json");
    expect(result.exploited.size).toBe(0);
  });

  test("rejects an empty feed list instead of degrading to no source", () => {
    expect(() => new CisaKevProvider(loader(), httpStub(async () => ({})), [])).toThrow(/at least one KEV feed/);
  });
});
