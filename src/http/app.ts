import express, { type NextFunction, type Request, type RequestHandler, type Response } from "express";
import { readFile } from "node:fs/promises";
import type { HistoryStore } from "../data/history.ts";
import type { ThreatIntelStore } from "../data/threat-intel.ts";
import type { OmniIntelligence } from "../services.ts";
import type { UrlRiskService } from "../services/url-risk.ts";
import type { PaidRequestStore } from "../data/paid-requests.ts";
import { CircleTransferLookup } from "../payments/circle-transfers.ts";
import { concurrencyGate } from "./concurrency-gate.ts";
import { PaidRouteIntegration, type GatewayWithHooks } from "./paid-route.ts";
import { dependenciesBody, endpointQuery, packageQuery, repoQuery, urlRiskQuery } from "./validation.ts";

function asyncRoute(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => void fn(req, res).catch(next);
}

function resolvePublicBaseUrl(req: Request, configured: string | undefined): string | undefined {
  if (configured !== undefined) return configured.replace(/\/$/, "");
  const forwardedHost = String(req.headers["x-forwarded-host"] ?? req.headers.host ?? "");
  if (!forwardedHost) return undefined;
  const forwardedProto = String(req.headers["x-forwarded-proto"] ?? req.protocol ?? "http").split(",")[0]!.trim();
  return `${forwardedProto}://${forwardedHost}`.replace(/\/$/, "");
}

const validatePackage: RequestHandler = (req, res, next) => {
  if (!packageQuery.safeParse(req.query).success) return void res.status(400).json({ error: "invalid_request" });
  next();
};

const validateRepo: RequestHandler = (req, res, next) => {
  if (!repoQuery.safeParse(req.query).success) return void res.status(400).json({ error: "invalid_request" });
  next();
};

const validateDependencies: RequestHandler = (req, res, next) => {
  if (!dependenciesBody.safeParse(req.body).success) return void res.status(400).json({ error: "invalid_request" });
  next();
};

const validateEndpoint: RequestHandler = (req, res, next) => {
  if (!endpointQuery.safeParse(req.query).success) return void res.status(400).json({ error: "invalid_request" });
  next();
};

const validateUrlRisk: RequestHandler = (req, res, next) => {
  if (!urlRiskQuery.safeParse(req.query).success) return void res.status(400).json({ error: "invalid_request" });
  next();
};

export function createApp(options: {
  omni: OmniIntelligence;
  urlRisk?: UrlRiskService;
  history: HistoryStore;
  threatIntel: ThreatIntelStore;
  gateway: GatewayWithHooks;
  paidRequests: PaidRequestStore;
  circleTransfers: CircleTransferLookup;
  maxInFlight: number;
  executionLeaseMs?: number;
  publicBaseUrl?: string | undefined;
}) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.use(express.json({ limit: "256kb", strict: true }));

  app.get("/health", (_req, res) => res.json({ service: "OMNI", status: "healthy" }));
  app.get("/ready", asyncRoute(async (_req, res) => {
    const [historyAvailable, threatStatus, paidRequestsAvailable] = await Promise.all([
      options.history.isAvailable(),
      options.threatIntel.status(),
      options.paidRequests.isAvailable()
    ]);
    res.status(paidRequestsAvailable ? 200 : 503).json({
      service: "OMNI",
      status: paidRequestsAvailable ? "ready" : "degraded",
      dependencies: {
        historyStore: historyAvailable ? "available" : "degraded",
        threatIntelligence: !threatStatus.available ? "degraded" : threatStatus.configured ? "configured" : "unconfigured",
        paidRequests: paidRequestsAvailable ? "available" : "unavailable"
      }
    });
  }));
  app.get("/llms.txt", asyncRoute(async (_req, res) => {
    const body = await readFile(new URL("../../llms.txt", import.meta.url), "utf8");
    const baseUrl = resolvePublicBaseUrl(_req, options.publicBaseUrl);
    const rendered = baseUrl ? body.replaceAll("https://omni.example.com", baseUrl) : body;
    res.type("text/plain; charset=utf-8").send(rendered);
  }));
  app.get("/openapi.yaml", asyncRoute(async (req, res) => {
    const body = await readFile(new URL("../../openapi.yaml", import.meta.url), "utf8");
    const baseUrl = resolvePublicBaseUrl(req, options.publicBaseUrl);
    const rendered = baseUrl
      ? body.replaceAll("https://omni.example.com", baseUrl)
      : body;
    res.type("application/yaml").send(rendered);
  }));

  const gate = concurrencyGate(options.maxInFlight);
  const paid = new PaidRouteIntegration(options.gateway, options.paidRequests, options.circleTransfers, options.executionLeaseMs);
  paid.installGatewayHooks();

  app.get("/v1/package/risk", validatePackage, gate, paid.route({
    route: "package",
    price: "$0.005",
    parse: req => packageQuery.parse(req.query),
    execute: input => options.omni.packageRisk(input.ecosystem, input.name, input.version)
  }));

  app.get("/v1/repo/risk", validateRepo, gate, paid.route({
    route: "repository",
    price: "$0.01",
    parse: req => repoQuery.parse(req.query),
    execute: input => options.omni.repositoryRisk(input.owner, input.repo)
  }));

  app.post("/v1/dependencies/risk", validateDependencies, gate, paid.route({
    route: "dependencies",
    price: "$0.05",
    parse: req => dependenciesBody.parse(req.body),
    execute: input => options.omni.dependenciesRisk(input.packages)
  }));

  app.get("/v1/x402/endpoint/preflight", validateEndpoint, gate, paid.route({
    route: "endpoint_preflight",
    price: "$0.01",
    parse: req => endpointQuery.parse(req.query),
    execute: input => options.omni.endpointPreflight(input.url)
  }));

  app.get("/v1/url/risk", validateUrlRisk, gate, paid.route({
    route: "url_risk",
    price: "$0.01",
    parse: req => urlRiskQuery.parse(req.query),
    execute: input => options.urlRisk ? options.urlRisk.assess(input.url) : Promise.reject(new Error("url risk service unavailable"))
  }));

  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const message = error instanceof Error ? error.message : "internal error";
    console.error(JSON.stringify({ level: "error", message }));
    res.status(500).json({ error: "internal_error" });
  });

  return app;
}
