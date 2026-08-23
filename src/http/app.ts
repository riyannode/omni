import express, { type NextFunction, type Request, type RequestHandler, type Response } from "express";
import { readFile } from "node:fs/promises";
import type { HistoryStore } from "../data/history.ts";
import type { ThreatIntelStore } from "../data/threat-intel.ts";
import type { OmniIntelligence } from "../services.ts";
import { concurrencyGate } from "./concurrency-gate.ts";
import { dependenciesBody, endpointQuery, packageQuery, repoQuery } from "./validation.ts";

function asyncRoute(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => void fn(req, res).catch(next);
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

export function createApp(options: {
  omni: OmniIntelligence;
  history: HistoryStore;
  threatIntel: ThreatIntelStore;
  gateway: { require(price: string): RequestHandler };
  maxInFlight: number;
  publicBaseUrl?: string | undefined;
}) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.use(express.json({ limit: "256kb", strict: true }));

  app.get("/health", (_req, res) => res.json({ service: "OMNI", status: "healthy" }));
  app.get("/ready", asyncRoute(async (_req, res) => {
    const [historyAvailable, threatStatus] = await Promise.all([options.history.isAvailable(), options.threatIntel.status()]);
    res.json({
      service: "OMNI",
      status: "ready",
      dependencies: {
        historyStore: historyAvailable ? "available" : "degraded",
        threatIntelligence: !threatStatus.available ? "degraded" : threatStatus.configured ? "configured" : "unconfigured"
      }
    });
  }));
  app.get("/llms.txt", asyncRoute(async (_req, res) => {
    const body = await readFile(new URL("../../llms.txt", import.meta.url), "utf8");
    res.type("text/plain; charset=utf-8").send(body);
  }));
  app.get("/openapi.yaml", asyncRoute(async (req, res) => {
    const body = await readFile(new URL("../../openapi.yaml", import.meta.url), "utf8");
    const forwardedHost = String(req.headers["x-forwarded-host"] ?? req.headers.host ?? "");
    const forwardedProto = String(req.headers["x-forwarded-proto"] ?? req.protocol ?? "http").split(",")[0]!.trim();
    const baseUrl = options.publicBaseUrl ?? (forwardedHost ? `${forwardedProto}://${forwardedHost}` : undefined);
    const rendered = baseUrl
      ? body.replaceAll("https://omni.example.com", baseUrl.replace(/\/$/, ""))
      : body;
    res.type("application/yaml").send(rendered);
  }));

  const gate = concurrencyGate(options.maxInFlight);

  app.get("/v1/package/risk", validatePackage, gate, options.gateway.require("$0.005"), asyncRoute(async (req, res) => {
    const input = packageQuery.parse(req.query);
    res.json(await options.omni.packageRisk(input.ecosystem, input.name, input.version));
  }));

  app.get("/v1/repo/risk", validateRepo, gate, options.gateway.require("$0.01"), asyncRoute(async (req, res) => {
    const input = repoQuery.parse(req.query);
    res.json(await options.omni.repositoryRisk(input.owner, input.repo));
  }));

  app.post("/v1/dependencies/risk", validateDependencies, gate, options.gateway.require("$0.05"), asyncRoute(async (req, res) => {
    const input = dependenciesBody.parse(req.body);
    res.json(await options.omni.dependenciesRisk(input.packages));
  }));

  app.get("/v1/x402/endpoint/preflight", validateEndpoint, gate, options.gateway.require("$0.01"), asyncRoute(async (req, res) => {
    const input = endpointQuery.parse(req.query);
    res.json(await options.omni.endpointPreflight(input.url));
  }));

  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const message = error instanceof Error ? error.message : "internal error";
    console.error(JSON.stringify({ level: "error", message }));
    res.status(500).json({ error: "internal_error" });
  });

  return app;
}
