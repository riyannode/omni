import { config } from "./config.ts";
import { createCache, CachedLoader } from "./data/cache.ts";
import { createHistoryStore } from "./data/history.ts";
import { CircleDiscoveryProvider } from "./providers/circle-discovery.ts";
import { UpstreamHttp } from "./providers/http.ts";

const cache = new CachedLoader(createCache(config.REDIS_URL));
const history = createHistoryStore(config.DATABASE_URL);
const http = new UpstreamHttp(config.UPSTREAM_TIMEOUT_MS, config.UPSTREAM_MAX_IN_FLIGHT, config.UPSTREAM_MAX_QUEUE);
const circle = new CircleDiscoveryProvider(cache, history, http);

if (!config.DATABASE_URL) {
  throw new Error("worker requires DATABASE_URL because its job is to build OMNI-owned history");
}

const intervalMs = 5 * 60 * 1000;
while (true) {
  const started = Date.now();
  try {
    const count = await circle.snapshotMarketplace();
    console.log(JSON.stringify({ level: "info", task: "circle_snapshot", count, durationMs: Date.now() - started }));
  } catch (error) {
    console.error(JSON.stringify({ level: "error", task: "circle_snapshot", message: error instanceof Error ? error.message : "unknown" }));
  }
  await Bun.sleep(intervalMs);
}
