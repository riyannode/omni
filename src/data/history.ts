import { createHash } from "node:crypto";
import { SQL } from "bun";
import type { EndpointHistory } from "../domain/risk.ts";

export type EndpointObservation = {
  resource: string;
  providerName?: string;
  payTo?: string;
  method?: string;
  priceAtomic?: string;
  network?: string;
  schemaHash?: string;
  supportsGateway?: boolean;
  supportsVanilla?: boolean;
};

export interface HistoryStore {
  recordEndpoint(observation: EndpointObservation): Promise<void>;
  endpointHistory(resource: string, currentPayTo?: string): Promise<EndpointHistory | undefined>;
  isAvailable(): Promise<boolean>;
}

class NoopHistoryStore implements HistoryStore {
  async recordEndpoint(): Promise<void> {}
  async endpointHistory(): Promise<EndpointHistory | undefined> { return undefined; }
  async isAvailable(): Promise<boolean> { return false; }
}

function fingerprint(o: EndpointObservation): string {
  return createHash("sha256").update(JSON.stringify([
    o.resource,
    o.providerName ?? null,
    o.payTo ?? null,
    o.method ?? null,
    o.priceAtomic ?? null,
    o.network ?? null,
    o.schemaHash ?? null,
    o.supportsGateway ?? null,
    o.supportsVanilla ?? null
  ])).digest("hex");
}

type ObservationRow = {
  provider_name: string | null;
  pay_to: string | null;
  price_atomic: string | null;
  network: string | null;
  schema_hash: string | null;
  observed_at: Date | string;
};

function changed<T>(rows: ObservationRow[], select: (row: ObservationRow) => T): number {
  let count = 0;
  for (let i = 1; i < rows.length; i += 1) {
    if (select(rows[i]!) !== select(rows[i - 1]!)) count += 1;
  }
  return count;
}

class PostgresHistoryStore implements HistoryStore {
  private readonly db: SQL;

  constructor(url: string) {
    this.db = new SQL(url, { max: 20, idleTimeout: 30, connectionTimeout: 5 });
  }

  async recordEndpoint(o: EndpointObservation): Promise<void> {
    const fp = fingerprint(o);
    await this.db`
      WITH previous AS (
        SELECT fingerprint FROM endpoint_state WHERE resource = ${o.resource}
      ), inserted AS (
        INSERT INTO endpoint_observations
          (resource, fingerprint, provider_name, pay_to, method, price_atomic, network, schema_hash, supports_gateway, supports_vanilla)
        SELECT
          ${o.resource}, ${fp}, ${o.providerName ?? null}, ${o.payTo ?? null}, ${o.method ?? null},
          ${o.priceAtomic ?? null}, ${o.network ?? null}, ${o.schemaHash ?? null},
          ${o.supportsGateway ?? null}, ${o.supportsVanilla ?? null}
        WHERE NOT EXISTS (SELECT 1 FROM previous WHERE fingerprint = ${fp})
      )
      INSERT INTO endpoint_state (resource, fingerprint)
      VALUES (${o.resource}, ${fp})
      ON CONFLICT (resource) DO UPDATE SET
        fingerprint = EXCLUDED.fingerprint,
        last_seen_at = now()
    `;
  }

  async endpointHistory(resource: string, currentPayTo?: string): Promise<EndpointHistory | undefined> {
    const rows = await this.db<ObservationRow[]>`
      SELECT provider_name, pay_to, price_atomic, network, schema_hash, observed_at
      FROM endpoint_observations
      WHERE resource = ${resource}
      ORDER BY observed_at ASC
      LIMIT 1000
    `;
    if (rows.length === 0) return {
      observationCount: 0,
      payToChangeCount: 0,
      priceChangeCount: 0,
      networkChangeCount: 0,
      schemaChangeCount: 0,
      providerChangeCount: 0,
      relatedResourcesByPayTo: 0
    };
    let relatedResourcesByPayTo = 0;
    if (currentPayTo) {
      const related = await this.db<{ count: number }[]>`
        SELECT count(DISTINCT resource)::int AS count
        FROM endpoint_observations
        WHERE lower(pay_to) = ${currentPayTo.toLowerCase()} AND resource <> ${resource}
      `;
      relatedResourcesByPayTo = related[0]?.count ?? 0;
    }
    const first = rows[0]!;
    const last = rows[rows.length - 1]!;
    return {
      observationCount: rows.length,
      firstSeenAt: new Date(first.observed_at).toISOString(),
      lastSeenAt: new Date(last.observed_at).toISOString(),
      payToChangeCount: changed(rows, row => row.pay_to),
      priceChangeCount: changed(rows, row => row.price_atomic),
      networkChangeCount: changed(rows, row => row.network),
      schemaChangeCount: changed(rows, row => row.schema_hash),
      providerChangeCount: changed(rows, row => row.provider_name),
      relatedResourcesByPayTo
    };
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.db`SELECT 1`;
      return true;
    } catch {
      return false;
    }
  }
}

export function createHistoryStore(databaseUrl?: string): HistoryStore {
  return databaseUrl ? new PostgresHistoryStore(databaseUrl) : new NoopHistoryStore();
}
