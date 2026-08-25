import { createHash } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { GatewayMiddleware } from "@circle-fin/x402-batching/server";
import { getAddress } from "viem";
import type {
  PaidRequest,
  PaidRequestStore,
  PaymentMetadata
} from "../data/paid-requests.ts";
import { CircleTransferLookup, type ExpectedTransfer } from "../payments/circle-transfers.ts";
import { negotiateResultRepresentation, sendResult } from "./result-representation.ts";

const IDEMPOTENCY_KEY_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DEFAULT_EXECUTION_LEASE_MS = 30_000;

type GatewayBeforeSettleHook = Parameters<GatewayMiddleware["onBeforeSettle"]>[0];
type GatewayAfterSettleHook = Parameters<GatewayMiddleware["onAfterSettle"]>[0];
type GatewaySettleFailureHook = Parameters<GatewayMiddleware["onSettleFailure"]>[0];
type GatewayVerifyFailureHook = Parameters<GatewayMiddleware["onVerifyFailure"]>[0];
type RouteInput = Record<string, unknown> | Array<unknown>;

type PaidRouteSpec<T extends RouteInput> = {
  route: string;
  price: string;
  parse(req: Request): T;
  execute(input: T): Promise<unknown>;
};

type PaymentContext = {
  readonly idempotencyKey: string;
  readonly requestFingerprint: string;
  readonly route: string;
  paymentNonce?: string;
  beforeSettleEntered: boolean;
  durablePaymentMetadataRecorded: boolean;
};

type ExecutionLeaseHeartbeat = {
  stop(): Promise<void>;
};

export type GatewayWithHooks = {
  require(price: string): unknown;
  onBeforeSettle?: (hook: GatewayBeforeSettleHook) => unknown;
  onAfterSettle?: (hook: GatewayAfterSettleHook) => unknown;
  onSettleFailure?: (hook: GatewaySettleFailureHook) => unknown;
  onVerifyFailure?: (hook: GatewayVerifyFailureHook) => unknown;
};

function sendError(res: Response, status: number, error: string, retryable = false): void {
  if (res.headersSent) return;
  res.status(status).json({ error, retryable });
}

function isPaymentSignaturePresent(req: Request): boolean {
  return req.headers["payment-signature"] !== undefined;
}

function readIdempotencyKey(req: Request): string | undefined {
  const value = req.headers["idempotency-key"];
  return typeof value === "string" && IDEMPOTENCY_KEY_PATTERN.test(value) ? value.toLowerCase() : undefined;
}

function fingerprint(route: string, method: string, input: RouteInput): string {
  return createHash("sha256")
    .update(JSON.stringify({ route, method: method.toUpperCase(), input }))
    .digest("hex");
}

function readAuthorization(payload: unknown): { nonce: string; payer?: string } | undefined {
  if (typeof payload !== "object" || payload === null) return undefined;
  const record = payload as Record<string, unknown>;
  const authorization = record.authorization;
  if (typeof authorization !== "object" || authorization === null) return undefined;
  const fields = authorization as Record<string, unknown>;
  if (typeof fields.nonce !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(fields.nonce)) return undefined;
  if (typeof fields.from !== "string") return undefined;
  let payer: string;
  try {
    payer = getAddress(fields.from as `0x${string}`);
  } catch {
    return undefined;
  }
  return {
    nonce: fields.nonce,
    payer
  };
}

function paymentMetadataFromRequest(
  payload: unknown,
  requirements: { network: string; payTo: string; asset: string; amount: string }
): PaymentMetadata | undefined {
  const authorization = readAuthorization(payload);
  if (!authorization) return undefined;
  return {
    paymentNonce: authorization.nonce,
    ...(authorization.payer === undefined ? {} : { payer: authorization.payer }),
    network: requirements.network,
    payTo: requirements.payTo,
    asset: requirements.asset,
    amountAtomic: requirements.amount
  };
}

function expectedTransfer(request: PaidRequest): ExpectedTransfer | undefined {
  if (!request.paymentNonce || !request.network || !request.payTo || !request.asset || !request.amountAtomic) return undefined;
  return {
    nonce: request.paymentNonce,
    ...(request.payer === undefined ? {} : { payer: request.payer }),
    payTo: request.payTo,
    network: request.network,
    asset: request.asset,
    amountAtomic: request.amountAtomic
  };
}

export class PaidRouteIntegration {
  private readonly requestContext = new AsyncLocalStorage<PaymentContext>();
  private readonly executionLeaseMs: number;

  constructor(
    private readonly gateway: GatewayWithHooks,
    private readonly store: PaidRequestStore,
    private readonly transfers: CircleTransferLookup,
    executionLeaseMs = DEFAULT_EXECUTION_LEASE_MS
  ) {
    this.executionLeaseMs = executionLeaseMs;
  }

  installGatewayHooks(): void {
    this.gateway.onBeforeSettle?.(this.beforeSettle);
    this.gateway.onAfterSettle?.(this.afterSettle);
    this.gateway.onSettleFailure?.(this.onSettleFailure);
    this.gateway.onVerifyFailure?.(this.onVerifyFailure);
  }

  route<T extends RouteInput>(spec: PaidRouteSpec<T>): RequestHandler {
    return (req, res, next) => {
      void this.handle(spec, req, res, next).catch(next);
    };
  }

  private readonly beforeSettle: GatewayBeforeSettleHook = async (context) => {
    const requestContext = this.requestContext.getStore();
    if (!requestContext) return;
    requestContext.beforeSettleEntered = true;
    const metadata = paymentMetadataFromRequest(context.paymentPayload.payload, context.requirements);
    if (!metadata) {
      await this.releaseUnsettledAttempt(requestContext);
      return { abort: true, reason: "payment_nonce_unavailable", message: "Payment nonce could not be safely persisted before settlement" };
    }
    try {
      await this.store.persistPaymentNonce(requestContext.idempotencyKey, requestContext.requestFingerprint, metadata);
      requestContext.paymentNonce = metadata.paymentNonce;
    } catch (error) {
      console.error(JSON.stringify({
        level: "error",
        event: "paid_request_nonce_persistence_failed",
        idempotencyKey: requestContext.idempotencyKey,
        route: requestContext.route,
        message: error instanceof Error ? error.message : "unknown error"
      }));
      return { abort: true, reason: "paid_request_store_unavailable", message: "Paid request state is unavailable" };
    }
  };

  private readonly afterSettle: GatewayAfterSettleHook = async (context) => {
    const requestContext = this.requestContext.getStore();
    if (!requestContext || !context.result.success || !context.result.transaction || !requestContext.paymentNonce) return;
    const metadata = paymentMetadataFromRequest(context.paymentPayload.payload, context.requirements);
    if (!metadata) return;
    try {
      await this.store.markPaid(requestContext.idempotencyKey, requestContext.requestFingerprint, context.result.transaction, metadata);
      requestContext.durablePaymentMetadataRecorded = true;
      console.log(JSON.stringify({
        level: "info",
        event: "paid_request_settled",
        idempotencyKey: requestContext.idempotencyKey,
        route: requestContext.route,
        circleTransferId: context.result.transaction
      }));
    } catch (error) {
      console.error(JSON.stringify({
        level: "error",
        event: "paid_request_settlement_persistence_failed",
        idempotencyKey: requestContext.idempotencyKey,
        route: requestContext.route,
        circleTransferId: context.result.transaction,
        message: error instanceof Error ? error.message : "unknown error"
      }));
    }
  };

  private readonly onSettleFailure: GatewaySettleFailureHook = async (context) => {
    const requestContext = this.requestContext.getStore();
    if (!requestContext) return;
    console.error(JSON.stringify({
      level: "error",
      event: "paid_request_settlement_uncertain",
      idempotencyKey: requestContext.idempotencyKey,
      route: requestContext.route,
      message: context.error instanceof Error ? context.error.message : "unknown error"
    }));
  };

  private readonly onVerifyFailure: GatewayVerifyFailureHook = async () => {
    const requestContext = this.requestContext.getStore();
    if (requestContext && !requestContext.paymentNonce) await this.releaseUnsettledAttempt(requestContext);
  };

  private async handle<T extends RouteInput>(spec: PaidRouteSpec<T>, req: Request, res: Response, next: NextFunction): Promise<void> {
    let input: T;
    try {
      input = spec.parse(req);
    } catch {
      sendError(res, 400, "invalid_request");
      return;
    }
    const keyHeader = req.headers["idempotency-key"];
    if (typeof keyHeader !== "string" || !IDEMPOTENCY_KEY_PATTERN.test(keyHeader)) {
      sendError(res, 400, "idempotency_key_invalid");
      return;
    }
    const accept = req.headers.accept;
    if (negotiateResultRepresentation(accept) === undefined) {
      sendError(res, 406, "not_acceptable");
      return;
    }
    const idempotencyKey = readIdempotencyKey(req)!;
    const requestFingerprint = fingerprint(spec.route, req.method, input);
    const paymentPresent = isPaymentSignaturePresent(req);
    let existing: PaidRequest | undefined;
    try {
      existing = await this.store.get(idempotencyKey);
    } catch (error) {
      if (!paymentPresent) {
        await this.invokeGatewayWithoutRecord(spec, req, res);
        return;
      }
      this.storeUnavailable(res, error, spec.route, idempotencyKey);
      return;
    }

    if (existing && existing.requestFingerprint !== requestFingerprint) {
      sendError(res, 409, "idempotency_conflict");
      return;
    }
    if (existing?.state === "completed") {
      this.replay(existing, res, accept);
      return;
    }
    if (existing?.state === "paid" || existing?.state === "running") {
      await this.resume(existing, input, spec, res, accept);
      return;
    }
    if (existing?.state === "settling" || existing?.state === "recovery_pending") {
      if (!existing.paymentNonce) {
        let released: boolean;
        try {
          released = await this.store.releasePaymentAttempt(existing.idempotencyKey, existing.requestFingerprint);
        } catch (error) {
          this.storeUnavailable(res, error, spec.route, existing.idempotencyKey);
          return;
        }
        if (!released) {
          let current: PaidRequest | undefined;
          try {
            current = await this.store.get(existing.idempotencyKey);
          } catch (error) {
            this.storeUnavailable(res, error, spec.route, existing.idempotencyKey);
            return;
          }
          if (current?.state === "completed") {
            this.replay(current, res, accept);
            return;
          }
          if (current?.state === "paid" || current?.state === "running") {
            await this.resume(current, input, spec, res, accept);
            return;
          }
          sendError(res, 409, "request_in_progress", true);
          return;
        }
        if (!paymentPresent) {
          await this.invokeGatewayWithoutRecord(spec, req, res);
          return;
        }
        let claimed: boolean;
        try {
          claimed = await this.store.claimPaymentAttempt(existing.idempotencyKey, existing.requestFingerprint);
        } catch (error) {
          this.storeUnavailable(res, error, spec.route, existing.idempotencyKey);
          return;
        }
        if (!claimed) {
          sendError(res, 409, "request_in_progress", true);
          return;
        }
        await this.invokeGatewayForClaimedRequest(spec, input, existing.idempotencyKey, existing.requestFingerprint, req, res, next);
        return;
      }
      await this.reconcile(existing, input, spec, res, accept);
      return;
    }
    if (!paymentPresent) {
      await this.invokeGatewayWithoutRecord(spec, req, res);
      return;
    }

    let reservation;
    try {
      reservation = await this.store.reserve(idempotencyKey, requestFingerprint, spec.route);
    } catch (error) {
      this.storeUnavailable(res, error, spec.route, idempotencyKey);
      return;
    }
    if (reservation.kind === "conflict") {
      sendError(res, 409, "idempotency_conflict");
      return;
    }
    if (reservation.request.state === "completed") {
      this.replay(reservation.request, res, accept);
      return;
    }
    let claimed: boolean;
    try {
      claimed = await this.store.claimPaymentAttempt(idempotencyKey, requestFingerprint);
    } catch (error) {
      this.storeUnavailable(res, error, spec.route, idempotencyKey);
      return;
    }
    if (!claimed) {
      sendError(res, 409, "request_in_progress", true);
      return;
    }
    await this.invokeGatewayForClaimedRequest(spec, input, idempotencyKey, requestFingerprint, req, res, next);
  }

  private async invokeGatewayWithoutRecord<T extends RouteInput>(spec: PaidRouteSpec<T>, req: Request, res: Response): Promise<void> {
    const middleware = this.gateway.require(spec.price) as RequestHandler;
    await middleware(req, res, async () => {
      sendError(res, 503, "paid_request_store_required", true);
    });
  }

  private async invokeGatewayForClaimedRequest<T extends RouteInput>(spec: PaidRouteSpec<T>, input: T, idempotencyKey: string, requestFingerprint: string, req: Request, res: Response, next: NextFunction): Promise<void> {
    const context: PaymentContext = {
      idempotencyKey,
      requestFingerprint,
      route: spec.route,
      beforeSettleEntered: false,
      durablePaymentMetadataRecorded: false
    };
    await this.requestContext.run(context, async () => {
      const middleware = this.gateway.require(spec.price) as RequestHandler;
      await middleware(req, res, async (error?: unknown) => {
        if (error) {
          next(error);
          return;
        }
        if (!context.durablePaymentMetadataRecorded) {
          sendError(res, 503, "recovery_pending", true);
          return;
        }
        await this.execute(input, spec, idempotencyKey, requestFingerprint, res, req.headers.accept);
      });
      if (!context.beforeSettleEntered && !context.paymentNonce) await this.releaseUnsettledAttempt(context);
    });
  }

  private async releaseUnsettledAttempt(context: PaymentContext): Promise<void> {
    try {
      await this.store.releasePaymentAttempt(context.idempotencyKey, context.requestFingerprint);
    } catch (error) {
      console.error(JSON.stringify({
        level: "error",
        event: "paid_request_attempt_release_failed",
        idempotencyKey: context.idempotencyKey,
        route: context.route,
        message: error instanceof Error ? error.message : "unknown error"
      }));
    }
  }

  private async resume<T extends RouteInput>(request: PaidRequest, input: T, spec: PaidRouteSpec<T>, res: Response, accept: string | undefined): Promise<void> {
    await this.execute(input, spec, request.idempotencyKey, request.requestFingerprint, res, accept);
  }

  private async reconcile<T extends RouteInput>(request: PaidRequest, input: T, spec: PaidRouteSpec<T>, res: Response, accept: string | undefined): Promise<void> {
    const expected = expectedTransfer(request);
    if (!expected) {
      await this.markRecoveryPending(request, res);
      sendError(res, 503, "recovery_pending", true);
      return;
    }
    const recovery = await this.transfers.byNonce(expected);
    if (recovery.kind === "accepted") {
      const metadata: PaymentMetadata = {
        paymentNonce: expected.nonce,
        ...(request.payer === undefined ? {} : { payer: request.payer }),
        network: expected.network,
        payTo: expected.payTo,
        asset: expected.asset,
        amountAtomic: expected.amountAtomic
      };
      try {
        await this.store.markPaid(request.idempotencyKey, request.requestFingerprint, recovery.transfer.id, metadata);
      } catch (error) {
        this.storeUnavailable(res, error, request.route, request.idempotencyKey);
        return;
      }
      let paid: PaidRequest | undefined;
      try {
        paid = await this.store.get(request.idempotencyKey);
      } catch (error) {
        this.storeUnavailable(res, error, request.route, request.idempotencyKey);
        return;
      }
      if (!paid) {
        sendError(res, 503, "recovery_pending", true);
        return;
      }
      await this.execute(input, spec, paid.idempotencyKey, paid.requestFingerprint, res, accept);
      return;
    }
    await this.markRecoveryPending(request, res);
    if (recovery.kind === "failed") {
      sendError(res, 402, "payment_failed");
      return;
    }
    console.error(JSON.stringify({
      level: "error",
      event: "paid_request_reconciliation_failed",
      idempotencyKey: request.idempotencyKey,
      route: request.route,
      outcome: recovery.reason
    }));
    sendError(res, 503, "recovery_pending", true);
  }

  private async markRecoveryPending(request: PaidRequest, res: Response): Promise<void> {
    try {
      await this.store.markRecoveryPending(request.idempotencyKey, request.requestFingerprint);
    } catch (error) {
      this.storeUnavailable(res, error, request.route, request.idempotencyKey);
    }
  }

  private async execute<T extends RouteInput>(input: T, spec: PaidRouteSpec<T>, idempotencyKey: string, requestFingerprint: string, res: Response, accept: string | undefined): Promise<void> {
    let claim: Awaited<ReturnType<PaidRequestStore["claimExecution"]>>;
    try {
      claim = await this.store.claimExecution(idempotencyKey, requestFingerprint, this.executionLeaseMs);
    } catch (error) {
      this.storeUnavailable(res, error, spec.route, idempotencyKey);
      return;
    }
    if (claim === "completed") {
      let completed: PaidRequest | undefined;
      try {
        completed = await this.store.get(idempotencyKey);
      } catch (error) {
        this.storeUnavailable(res, error, spec.route, idempotencyKey);
        return;
      }
      if (completed) this.replay(completed, res, accept);
      else sendError(res, 503, "recovery_pending", true);
      return;
    }
    if (claim === "busy") {
      sendError(res, 409, "request_in_progress", true);
      return;
    }
    if (typeof claim !== "object" || claim.kind !== "claimed") {
      sendError(res, 503, "recovery_pending", true);
      return;
    }
    const leaseId = claim.leaseId;
    const heartbeat = this.startExecutionHeartbeat(idempotencyKey, requestFingerprint, leaseId);
    let result: unknown;
    try {
      result = await spec.execute(input);
    } catch (error) {
      await heartbeat.stop();
      try {
        await this.store.releaseExecution(idempotencyKey, requestFingerprint, leaseId);
      } catch (releaseError) {
        console.error(JSON.stringify({
          level: "error",
          event: "paid_request_execution_lease_release_failed",
          idempotencyKey,
          route: spec.route,
          message: releaseError instanceof Error ? releaseError.message : "unknown error"
        }));
      }
      console.error(JSON.stringify({
        level: "error",
        event: "paid_request_execution_failed",
        idempotencyKey,
        route: spec.route,
        message: error instanceof Error ? error.message : "unknown error"
      }));
      sendError(res, 500, "internal_error", true);
      return;
    }
    await heartbeat.stop();
    try {
      await this.store.complete(idempotencyKey, requestFingerprint, leaseId, result, 200);
      sendResult(res, 200, result, accept);
    } catch (error) {
      try {
        await this.store.releaseExecution(idempotencyKey, requestFingerprint, leaseId);
      } catch (releaseError) {
        console.error(JSON.stringify({
          level: "error",
          event: "paid_request_execution_lease_release_failed",
          idempotencyKey,
          route: spec.route,
          message: releaseError instanceof Error ? releaseError.message : "unknown error"
        }));
      }
      console.error(JSON.stringify({
        level: "error",
        event: "paid_request_completion_failed",
        idempotencyKey,
        route: spec.route,
        message: error instanceof Error ? error.message : "unknown error"
      }));
      sendError(res, 500, "internal_error", true);
    }
  }

  private startExecutionHeartbeat(idempotencyKey: string, requestFingerprint: string, leaseId: string): ExecutionLeaseHeartbeat {
    const intervalMs = Math.max(1, Math.floor(this.executionLeaseMs / 3));
    let stopped = false;
    let inFlight: Promise<void> | undefined;
    let timer: ReturnType<typeof setInterval> | undefined;
    const renew = () => {
      if (stopped || inFlight) return;
      inFlight = (async () => {
        try {
          const renewed = await this.store.renewExecution(idempotencyKey, requestFingerprint, leaseId);
          if (!renewed) {
            stopped = true;
            if (timer !== undefined) clearInterval(timer);
          }
        } catch (error) {
          console.error(JSON.stringify({
            level: "error",
            event: "paid_request_execution_lease_renew_failed",
            idempotencyKey,
            message: error instanceof Error ? error.message : "unknown error"
          }));
        } finally {
          inFlight = undefined;
        }
      })();
    };
    timer = setInterval(renew, intervalMs);
    timer.unref?.();
    return {
      stop: async () => {
        stopped = true;
        if (timer !== undefined) clearInterval(timer);
        if (inFlight) await inFlight;
      }
    };
  }

  private replay(request: PaidRequest, res: Response, accept: string | undefined): void {
    sendResult(res, request.finalStatus, request.finalResult, accept);
  }

  private storeUnavailable(res: Response, error: unknown, route: string, idempotencyKey: string): void {
    console.error(JSON.stringify({
      level: "error",
      event: "paid_request_store_unavailable",
      idempotencyKey,
      route,
      message: error instanceof Error ? error.message : "unknown error"
    }));
    sendError(res, 503, "paid_request_store_unavailable", true);
  }
}
