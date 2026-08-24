import { SQL } from "bun";
import { randomUUID } from "node:crypto";

export const PAID_REQUEST_STATES = [
  "waiting_payment",
  "settling",
  "paid",
  "running",
  "completed",
  "recovery_pending"
] as const;

export type PaidRequestState = typeof PAID_REQUEST_STATES[number];

export type PaidRequest = {
  idempotencyKey: string;
  requestFingerprint: string;
  route: string;
  state: PaidRequestState;
  paymentNonce?: string;
  circleTransferId?: string;
  payer?: string;
  network?: string;
  payTo?: string;
  asset?: string;
  amountAtomic?: string;
  finalResult?: unknown;
  finalStatus: number;
  createdAt: string;
  updatedAt: string;
  executionLeaseAt?: string;
  executionLeaseId?: string;
};

export type PaymentMetadata = {
  paymentNonce: string;
  payer?: string;
  network: string;
  payTo: string;
  asset: string;
  amountAtomic: string;
};

export type PaidRequestReservation =
  | { kind: "created"; request: PaidRequest }
  | { kind: "existing"; request: PaidRequest }
  | { kind: "conflict"; request: PaidRequest };

export type ExecutionClaim = { kind: "claimed"; leaseId: string } | "completed" | "busy" | "unavailable";

export interface PaidRequestStore {
  get(idempotencyKey: string): Promise<PaidRequest | undefined>;
  reserve(idempotencyKey: string, requestFingerprint: string, route: string): Promise<PaidRequestReservation>;
  claimPaymentAttempt(idempotencyKey: string, requestFingerprint: string): Promise<boolean>;
  persistPaymentNonce(idempotencyKey: string, requestFingerprint: string, metadata: PaymentMetadata): Promise<void>;
  markPaid(idempotencyKey: string, requestFingerprint: string, circleTransferId: string, metadata: PaymentMetadata): Promise<void>;
  markRecoveryPending(idempotencyKey: string, requestFingerprint: string): Promise<void>;
  claimExecution(idempotencyKey: string, requestFingerprint: string, leaseMs: number): Promise<ExecutionClaim>;
  renewExecution(idempotencyKey: string, requestFingerprint: string, leaseId: string): Promise<boolean>;
  releasePaymentAttempt(idempotencyKey: string, requestFingerprint: string): Promise<boolean>;
  releaseExecution(idempotencyKey: string, requestFingerprint: string, leaseId: string): Promise<void>;
  complete(idempotencyKey: string, requestFingerprint: string, leaseId: string, result: unknown, status: number): Promise<void>;
  isAvailable(): Promise<boolean>;
}

type PaidRequestRow = {
  idempotency_key: string;
  request_fingerprint: string;
  route: string;
  state: PaidRequestState;
  payment_nonce: string | null;
  circle_transfer_id: string | null;
  payer: string | null;
  network: string | null;
  pay_to: string | null;
  asset: string | null;
  amount_atomic: string | null;
  final_result: unknown | string | null;
  final_status: number;
  created_at: Date | string;
  updated_at: Date | string;
  execution_lease_at: Date | string | null;
  execution_lease_id: string | null;
};

function parseJson(value: unknown): unknown {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function toRequest(row: PaidRequestRow): PaidRequest {
  return {
    idempotencyKey: row.idempotency_key,
    requestFingerprint: row.request_fingerprint,
    route: row.route,
    state: row.state,
    ...(row.payment_nonce === null ? {} : { paymentNonce: row.payment_nonce }),
    ...(row.circle_transfer_id === null ? {} : { circleTransferId: row.circle_transfer_id }),
    ...(row.payer === null ? {} : { payer: row.payer }),
    ...(row.network === null ? {} : { network: row.network }),
    ...(row.pay_to === null ? {} : { payTo: row.pay_to }),
    ...(row.asset === null ? {} : { asset: row.asset }),
    ...(row.amount_atomic === null ? {} : { amountAtomic: row.amount_atomic }),
    ...(row.final_result === null ? {} : { finalResult: parseJson(row.final_result) }),
    finalStatus: row.final_status,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    ...(row.execution_lease_at === null ? {} : { executionLeaseAt: new Date(row.execution_lease_at).toISOString() }),
    ...(row.execution_lease_id === null ? {} : { executionLeaseId: row.execution_lease_id })
  };
}

class PostgresPaidRequestStore implements PaidRequestStore {
  private readonly db: SQL;

  constructor(url: string) {
    this.db = new SQL(url, { max: 20, idleTimeout: 30, connectionTimeout: 5 });
  }

  async get(idempotencyKey: string): Promise<PaidRequest | undefined> {
    const rows = await this.db<PaidRequestRow[]>`
      SELECT idempotency_key, request_fingerprint, route, state, payment_nonce, circle_transfer_id,
             payer, network, pay_to, asset, amount_atomic, final_result, final_status,
             created_at, updated_at, execution_lease_at, execution_lease_id
      FROM paid_requests
      WHERE idempotency_key = ${idempotencyKey}
    `;
    return rows[0] ? toRequest(rows[0]) : undefined;
  }

  async reserve(idempotencyKey: string, requestFingerprint: string, route: string): Promise<PaidRequestReservation> {
    const inserted = await this.db<{ idempotency_key: string }[]>`
      INSERT INTO paid_requests (idempotency_key, request_fingerprint, route)
      VALUES (${idempotencyKey}, ${requestFingerprint}, ${route})
      ON CONFLICT (idempotency_key) DO NOTHING
      RETURNING idempotency_key
    `;
    const request = await this.get(idempotencyKey);
    if (!request) throw new Error("paid request reservation disappeared");
    if (request.requestFingerprint !== requestFingerprint) return { kind: "conflict", request };
    return inserted.length > 0 ? { kind: "created", request } : { kind: "existing", request };
  }

  async claimPaymentAttempt(idempotencyKey: string, requestFingerprint: string): Promise<boolean> {
    const rows = await this.db<{ idempotency_key: string }[]>`
      UPDATE paid_requests
      SET state = 'settling', updated_at = now()
      WHERE idempotency_key = ${idempotencyKey}
        AND request_fingerprint = ${requestFingerprint}
        AND state = 'waiting_payment'
      RETURNING idempotency_key
    `;
    return rows.length > 0;
  }

  async persistPaymentNonce(idempotencyKey: string, requestFingerprint: string, metadata: PaymentMetadata): Promise<void> {
    const rows = await this.db<{ idempotency_key: string }[]>`
      UPDATE paid_requests
      SET payment_nonce = ${metadata.paymentNonce},
          payer = ${metadata.payer ?? null},
          network = ${metadata.network},
          pay_to = ${metadata.payTo},
          asset = ${metadata.asset},
          amount_atomic = ${metadata.amountAtomic},
          updated_at = now()
      WHERE idempotency_key = ${idempotencyKey}
        AND request_fingerprint = ${requestFingerprint}
        AND state = 'settling'
        AND (payment_nonce IS NULL OR payment_nonce = ${metadata.paymentNonce})
      RETURNING idempotency_key
    `;
    if (rows.length === 0) throw new Error("paid request is not claimable for nonce persistence");
  }

  async markPaid(idempotencyKey: string, requestFingerprint: string, circleTransferId: string, metadata: PaymentMetadata): Promise<void> {
    const rows = await this.db<{ idempotency_key: string }[]>`
      UPDATE paid_requests
      SET state = 'paid',
          circle_transfer_id = ${circleTransferId},
          payment_nonce = ${metadata.paymentNonce},
          payer = ${metadata.payer ?? null},
          network = ${metadata.network},
          pay_to = ${metadata.payTo},
          asset = ${metadata.asset},
          amount_atomic = ${metadata.amountAtomic},
          execution_lease_at = NULL,
          updated_at = now()
      WHERE idempotency_key = ${idempotencyKey}
        AND request_fingerprint = ${requestFingerprint}
        AND state IN ('settling', 'recovery_pending')
        AND payment_nonce = ${metadata.paymentNonce}
      RETURNING idempotency_key
    `;
    if (rows.length === 0) throw new Error("paid request is not in settling state");
  }

  async markRecoveryPending(idempotencyKey: string, requestFingerprint: string): Promise<void> {
    await this.db`
      UPDATE paid_requests
      SET state = 'recovery_pending', updated_at = now()
      WHERE idempotency_key = ${idempotencyKey}
        AND request_fingerprint = ${requestFingerprint}
        AND state IN ('settling', 'recovery_pending')
    `;
  }

  async releasePaymentAttempt(idempotencyKey: string, requestFingerprint: string): Promise<boolean> {
    const rows = await this.db<{ idempotency_key: string }[]>`
      UPDATE paid_requests
      SET state = 'waiting_payment', updated_at = now()
      WHERE idempotency_key = ${idempotencyKey}
        AND request_fingerprint = ${requestFingerprint}
        AND state IN ('settling', 'recovery_pending')
        AND payment_nonce IS NULL
      RETURNING idempotency_key
    `;
    return rows.length > 0;
  }

  async claimExecution(idempotencyKey: string, requestFingerprint: string, leaseMs: number): Promise<ExecutionClaim> {
    const leaseSeconds = Math.max(1, Math.ceil(leaseMs / 1000));
    const leaseId = randomUUID();
    const claimed = await this.db<{ idempotency_key: string }[]>`
      UPDATE paid_requests
      SET state = 'running', execution_lease_at = now(), execution_lease_id = ${leaseId}, updated_at = now()
      WHERE idempotency_key = ${idempotencyKey}
        AND request_fingerprint = ${requestFingerprint}
        AND (
          state = 'paid'
          OR (state = 'running' AND execution_lease_at < now() - (${leaseSeconds} * interval '1 second'))
        )
      RETURNING idempotency_key
    `;
    if (claimed.length > 0) return { kind: "claimed", leaseId };

    const request = await this.get(idempotencyKey);
    if (!request || request.requestFingerprint !== requestFingerprint) return "unavailable";
    if (request.state === "completed") return "completed";
    if (request.state === "running") return "busy";
    return "unavailable";
  }

  async releaseExecution(idempotencyKey: string, requestFingerprint: string, leaseId: string): Promise<void> {
    await this.db`
      UPDATE paid_requests
      SET state = 'paid', execution_lease_at = NULL, execution_lease_id = NULL, updated_at = now()
      WHERE idempotency_key = ${idempotencyKey}
        AND request_fingerprint = ${requestFingerprint}
        AND state = 'running'
        AND execution_lease_id = ${leaseId}
    `;
  }

  async renewExecution(idempotencyKey: string, requestFingerprint: string, leaseId: string): Promise<boolean> {
    const rows = await this.db<{ idempotency_key: string }[]>`
      UPDATE paid_requests
      SET execution_lease_at = now(), updated_at = now()
      WHERE idempotency_key = ${idempotencyKey}
        AND request_fingerprint = ${requestFingerprint}
        AND state = 'running'
        AND execution_lease_id = ${leaseId}
      RETURNING idempotency_key
    `;
    return rows.length > 0;
  }

  async complete(idempotencyKey: string, requestFingerprint: string, leaseId: string, result: unknown, status: number): Promise<void> {
    const rows = await this.db<{ idempotency_key: string }[]>`
      UPDATE paid_requests
      SET state = 'completed',
          final_result = ${JSON.stringify(result)}::jsonb,
          final_status = ${status},
          execution_lease_at = NULL,
          execution_lease_id = NULL,
          updated_at = now()
      WHERE idempotency_key = ${idempotencyKey}
        AND request_fingerprint = ${requestFingerprint}
        AND state = 'running'
        AND execution_lease_id = ${leaseId}
      RETURNING idempotency_key
    `;
    if (rows.length === 0) throw new Error("paid request execution claim expired or is missing");
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.db`SELECT 1 FROM paid_requests LIMIT 1`;
      return true;
    } catch {
      return false;
    }
  }
}

class UnavailablePaidRequestStore implements PaidRequestStore {
  private unavailable(): never {
    throw new Error("paid request store unavailable");
  }

  async get(): Promise<PaidRequest | undefined> { return this.unavailable(); }
  async reserve(): Promise<PaidRequestReservation> { return this.unavailable(); }
  async claimPaymentAttempt(): Promise<boolean> { return this.unavailable(); }
  async persistPaymentNonce(): Promise<void> { return this.unavailable(); }
  async markPaid(): Promise<void> { return this.unavailable(); }
  async markRecoveryPending(): Promise<void> { return this.unavailable(); }
  async releasePaymentAttempt(): Promise<boolean> { return this.unavailable(); }
  async claimExecution(): Promise<ExecutionClaim> { return this.unavailable(); }
  async renewExecution(): Promise<boolean> { return this.unavailable(); }
  async releaseExecution(): Promise<void> { return this.unavailable(); }
  async complete(): Promise<void> { return this.unavailable(); }
  async isAvailable(): Promise<boolean> { return false; }
}

export function createPaidRequestStore(databaseUrl?: string): PaidRequestStore {
  return databaseUrl ? new PostgresPaidRequestStore(databaseUrl) : new UnavailablePaidRequestStore();
}
