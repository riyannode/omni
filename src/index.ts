import { config } from "./config.ts";
import { RiskEngine } from "./domain/risk-engine.ts";
import { createCache, CachedLoader } from "./data/cache.ts";
import { createHistoryStore } from "./data/history.ts";
import { createThreatIntelStore } from "./data/threat-intel.ts";
import { OsvProvider } from "./providers/osv.ts";
import { CisaKevProvider } from "./providers/cisa-kev.ts";
import { ScorecardProvider } from "./providers/scorecard.ts";
import { NpmRegistryProvider } from "./providers/npm-registry.ts";
import { CircleDiscoveryProvider } from "./providers/circle-discovery.ts";
import { X402Probe } from "./providers/x402-probe.ts";
import { UpstreamHttp } from "./providers/http.ts";
import { createCircleGateway } from "./payments/circle.ts";
import { OmniIntelligence } from "./services.ts";
import { createApp } from "./http/app.ts";

const cache = new CachedLoader(createCache(config.REDIS_URL));
const history = createHistoryStore(config.DATABASE_URL);
const threatIntel = createThreatIntelStore(config.DATABASE_URL);
const http = new UpstreamHttp(config.UPSTREAM_TIMEOUT_MS, config.UPSTREAM_MAX_IN_FLIGHT, config.UPSTREAM_MAX_QUEUE);
const circle = new CircleDiscoveryProvider(cache, history, http);
const omni = new OmniIntelligence(
  new RiskEngine(), cache,
  new OsvProvider(http), new CisaKevProvider(cache, http, config.kevFeedUrls.length > 0 ? config.kevFeedUrls : undefined), new ScorecardProvider(http), new NpmRegistryProvider(http),
  circle, new X402Probe(http, config.allowedEndpointHosts), history, threatIntel
);
const gateway = createCircleGateway(config.SELLER_ADDRESS as `0x${string}`, config.CIRCLE_FACILITATOR_URL);
const app = createApp({ omni, history, threatIntel, gateway, maxInFlight: config.MAX_IN_FLIGHT, publicBaseUrl: config.PUBLIC_BASE_URL });

const server = app.listen(config.PORT, () => console.log(JSON.stringify({ level: "info", service: "OMNI", port: config.PORT })));
server.keepAliveTimeout = 65_000;
server.headersTimeout = 66_000;

function shutdown(signal: string) {
  console.log(JSON.stringify({ level: "info", signal, message: "shutting down" }));
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
