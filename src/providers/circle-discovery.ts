import { createHash } from "node:crypto";
import type { Evidence } from "../domain/risk.ts";
import type { EndpointObservation, HistoryStore } from "../data/history.ts";
import { CachedLoader } from "../data/cache.ts";
import { UpstreamHttp } from "./http.ts";

type ObservedAccept = {
  scheme?: string;
  network?: string;
  amount?: string;
  asset?: string;
  payTo?: string;
};

type CircleItem = {
  resource: string;
  accepts?: ObservedAccept[];
  metadata?: {
    provider?: { name?: string };
    method?: string;
    input?: unknown;
    output?: unknown;
    supportsCircleGateway?: boolean;
    supportsVanillax402?: boolean;
  };
};
type CircleResponse = { items?: CircleItem[]; pagination?: { total?: number } };

function hashSchema(item: CircleItem): string {
  return createHash("sha256").update(JSON.stringify({ input: item.metadata?.input, output: item.metadata?.output })).digest("hex");
}

function observation(item: CircleItem): EndpointObservation {
  const first = item.accepts?.[0];
  return {
    resource: item.resource,
    ...(item.metadata?.provider?.name === undefined ? {} : { providerName: item.metadata.provider.name }),
    ...(first?.payTo === undefined ? {} : { payTo: first.payTo }),
    ...(item.metadata?.method === undefined ? {} : { method: item.metadata.method }),
    ...(first?.amount === undefined ? {} : { priceAtomic: first.amount }),
    ...(first?.network === undefined ? {} : { network: first.network }),
    schemaHash: hashSchema(item),
    ...(item.metadata?.supportsCircleGateway === undefined ? {} : { supportsGateway: item.metadata.supportsCircleGateway }),
    ...(item.metadata?.supportsVanillax402 === undefined ? {} : { supportsVanilla: item.metadata.supportsVanillax402 })
  };
}

export type ObservedPaymentRequirement = {
  scheme?: string;
  network?: string;
  amount?: string;
  asset?: string;
  payTo?: string;
};

export function observedPaymentOptions(item: CircleItem): ObservedPaymentRequirement[] {
  return (item.accepts ?? []).map(accept => ({
    ...(accept.scheme === undefined ? {} : { scheme: accept.scheme }),
    ...(accept.network === undefined ? {} : { network: accept.network }),
    ...(accept.amount === undefined ? {} : { amount: accept.amount }),
    ...(accept.asset === undefined ? {} : { asset: accept.asset }),
    ...(accept.payTo === undefined ? {} : { payTo: accept.payTo })
  }));
}

export class CircleDiscoveryProvider {
  constructor(
    private readonly cache: CachedLoader,
    private readonly history: HistoryStore,
    private readonly http: UpstreamHttp
  ) {}

  async findExact(resource: string): Promise<{ item?: CircleItem; observation?: EndpointObservation; paymentOptions: ObservedPaymentRequirement[]; evidence: Evidence }> {
    const q = new URL("https://api.circle.com/v2/x402/discovery/resources");
    q.searchParams.set("query", resource);
    q.searchParams.set("limit", "50");
    const cached = await this.cache.getOrLoadWithMetadata<CircleResponse>(`circle:v2:resource:${resource}`, 60, () => this.http.json<CircleResponse>(q.toString()));
    const data = cached.value;
    const item = (data.items ?? []).find(x => x.resource === resource);
    const state = item ? observation(item) : undefined;
    return {
      ...(item === undefined ? {} : { item }),
      ...(state === undefined ? {} : { observation: state }),
      paymentOptions: item ? observedPaymentOptions(item) : [],
      evidence: {
        source: "Circle Discovery",
        kind: "marketplace_listing",
        observedAt: cached.cachedAt,
        detail: state ?? { resource, listed: false },
        expiresAt: cached.expiresAt
      }
    };
  }

  async snapshotMarketplace(): Promise<number> {
    let offset = 0;
    let count = 0;
    while (true) {
      const q = new URL("https://api.circle.com/v2/x402/discovery/resources");
      q.searchParams.set("limit", "200");
      q.searchParams.set("offset", String(offset));
      const data = await this.http.json<CircleResponse>(q.toString());
      const items = data.items ?? [];
      for (const item of items) await this.history.recordEndpoint(observation(item));
      count += items.length;
      offset += items.length;
      if (items.length === 0 || offset >= (data.pagination?.total ?? count)) break;
    }
    return count;
  }
}
