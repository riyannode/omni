import { readFile } from "node:fs/promises";
import { BatchFacilitatorClient, createGatewayMiddleware } from "@circle-fin/x402-batching/server";
import { parse as parseYaml } from "yaml";

export function createCircleGateway(sellerAddress: `0x${string}`, facilitatorUrl?: string) {
  return createGatewayMiddleware({
    sellerAddress,
    ...(facilitatorUrl ? { facilitatorUrl } : {})
  });
}

export interface CircleDiscovery {
  getNetworks(): Promise<string[]>;
}

interface DiscoveryCache {
  networks: string[];
  fetchedAt: number;
}

const DISCOVERY_TTL_MS = 300_000;

export function createCircleDiscovery(facilitatorUrl?: string): CircleDiscovery {
  let cache: DiscoveryCache | undefined;

  return {
    async getNetworks(): Promise<string[]> {
      const client = new BatchFacilitatorClient({ url: facilitatorUrl ?? "https://gateway-api.circle.com" });

      try {
        const supported = await client.getSupported();
        const networks = [...new Set(
          supported.kinds
            .filter(kind => kind.x402Version === 2 && kind.scheme === "exact" && kind.network.trim() !== "")
            .map(kind => kind.network)
        )].sort();

        if (networks.length > 0) {
          cache = { networks, fetchedAt: Date.now() };
          return networks;
        }
      } catch {
        // fall through to cache
      }

      if (cache !== undefined && Date.now() - cache.fetchedAt < DISCOVERY_TTL_MS) {
        return cache.networks;
      }

      throw new Error("circle_gateway_discovery_unavailable");
    }
  };
}

export interface PaidResource {
  method: string;
  resource: string;
  price: {
    currency: string;
    amount: string;
  };
}

export interface X402Manifest {
  x402Version: number;
  service: string;
  description: string;
  openapi: string;
  paymentTerms: string;
  networks: string[];
  resources: PaidResource[];
}

interface PaymentInfo {
  price?: {
    mode?: string;
    currency?: string;
    amount?: string;
  };
  protocols?: unknown[];
}

interface OpenApiOperation {
  "x-payment-info"?: PaymentInfo;
}

function isPaidOperation(op: unknown): op is OpenApiOperation {
  return typeof op === "object" && op !== null && "x-payment-info" in op && typeof (op as Record<string, unknown>)["x-payment-info"] === "object";
}

export async function loadPaidResources(publicBaseUrl: string): Promise<PaidResource[]> {
  const raw = await readFile(new URL("../../openapi.yaml", import.meta.url), "utf8");
  const doc = parseYaml(raw) as { paths?: Record<string, Record<string, unknown>> };
  const paths = doc.paths ?? {};
  const resources: PaidResource[] = [];

  for (const [path, methods] of Object.entries(paths)) {
    if (typeof methods !== "object" || methods === null) continue;
    for (const [method, op] of Object.entries(methods as Record<string, unknown>)) {
      if (!isPaidOperation(op)) continue;
      const price = op["x-payment-info"]!.price;
      if (!price?.currency || !price?.amount) continue;
      resources.push({
        method: method.toUpperCase(),
        resource: `${publicBaseUrl}${path}`,
        price: { currency: price.currency, amount: price.amount }
      });
    }
  }

  return resources;
}
