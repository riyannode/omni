import { getAddress } from "viem";

const DEFAULT_CIRCLE_FACILITATOR_URL = "https://gateway-api.circle.com";
const ACCEPTED_STATUSES = new Set(["received", "batched", "confirmed", "completed"]);
const FAILED_STATUS = "failed";

type TransferStatus = "received" | "batched" | "confirmed" | "completed" | "failed";

export type CircleTransfer = {
  id: string;
  status: TransferStatus;
  token: string;
  sendingNetwork: string;
  recipientNetwork: string;
  fromAddress: string;
  toAddress: string;
  amount: string;
  nonce: string;
  txHash: string | null;
  asset?: string;
};

export type ExpectedTransfer = {
  nonce: string;
  payer?: string;
  payTo: string;
  network: string;
  asset: string;
  amountAtomic: string;
};

export type TransferRecovery =
  | { kind: "accepted"; transfer: CircleTransfer }
  | { kind: "failed"; transfer: CircleTransfer }
  | { kind: "unknown"; reason: string };

function transferEndpoint(baseUrl: string | undefined, nonce: string): URL {
  const url = new URL(baseUrl ?? DEFAULT_CIRCLE_FACILITATOR_URL);
  const pathname = url.pathname.replace(/\/+$/, "");
  if (pathname.endsWith("/v1/x402")) url.pathname = `${pathname}/transfers`;
  else if (pathname.endsWith("/v1")) url.pathname = `${pathname}/x402/transfers`;
  else url.pathname = `${pathname}/v1/x402/transfers`;
  url.search = new URLSearchParams({ nonce }).toString();
  return url;
}

function isAtomicAmount(value: string): boolean {
  return /^\d+$/.test(value);
}

function sameAddress(left: string, right: string): boolean {
  try {
    return getAddress(left as `0x${string}`) === getAddress(right as `0x${string}`);
  } catch {
    return false;
  }
}

function parseTransfer(value: unknown): CircleTransfer | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const row = value as Record<string, unknown>;
  if (
    typeof row.id !== "string" ||
    typeof row.status !== "string" ||
    typeof row.token !== "string" ||
    typeof row.sendingNetwork !== "string" ||
    typeof row.recipientNetwork !== "string" ||
    typeof row.fromAddress !== "string" ||
    typeof row.toAddress !== "string" ||
    typeof row.amount !== "string" ||
    typeof row.nonce !== "string" ||
    !(row.txHash === null || typeof row.txHash === "string") ||
    !(row.asset === undefined || typeof row.asset === "string")
  ) return undefined;
  if (![...ACCEPTED_STATUSES, FAILED_STATUS].includes(row.status)) return undefined;
  return {
    id: row.id,
    status: row.status as TransferStatus,
    token: row.token,
    sendingNetwork: row.sendingNetwork,
    recipientNetwork: row.recipientNetwork,
    fromAddress: row.fromAddress,
    toAddress: row.toAddress,
    amount: row.amount,
    nonce: row.nonce,
    txHash: row.txHash,
    ...(row.asset === undefined ? {} : { asset: row.asset })
  };
}

function matchesExpected(transfer: CircleTransfer, expected: ExpectedTransfer): boolean {
  if (transfer.nonce !== expected.nonce) return false;
  if (!isAtomicAmount(transfer.amount) || !isAtomicAmount(expected.amountAtomic)) return false;
  if (BigInt(transfer.amount) !== BigInt(expected.amountAtomic)) return false;
  if (transfer.sendingNetwork !== expected.network) return false;
  if (transfer.recipientNetwork !== expected.network) return false;
  if (!sameAddress(transfer.toAddress, expected.payTo)) return false;
  if (expected.payer !== undefined && !sameAddress(transfer.fromAddress, expected.payer)) return false;
  if (transfer.asset !== undefined && !sameAddress(transfer.asset, expected.asset)) return false;
  if (transfer.token.toUpperCase() !== "USDC") return false;
  return true;
}

export class CircleTransferLookup {
  constructor(
    private readonly facilitatorUrl: string | undefined,
    private readonly timeoutMs = 5_000
  ) {}

  async byNonce(expected: ExpectedTransfer): Promise<TransferRecovery> {
    let response: Response;
    try {
      response = await fetch(transferEndpoint(this.facilitatorUrl, expected.nonce), {
        method: "GET",
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(this.timeoutMs)
      });
    } catch {
      return { kind: "unknown", reason: "circle_transfer_lookup_unavailable" };
    }
    if (!response.ok) return { kind: "unknown", reason: `circle_transfer_lookup_http_${response.status}` };

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      return { kind: "unknown", reason: "circle_transfer_lookup_malformed" };
    }
    if (typeof body !== "object" || body === null || !Array.isArray((body as { transfers?: unknown }).transfers)) {
      return { kind: "unknown", reason: "circle_transfer_lookup_malformed" };
    }
    const rows = (body as { transfers: unknown[] }).transfers.map(parseTransfer);
    if (rows.some(row => row === undefined) || rows.length !== 1) {
      return { kind: "unknown", reason: rows.length === 0 ? "circle_transfer_not_found" : "circle_transfer_ambiguous" };
    }
    const transfer = rows[0]!;
    if (!matchesExpected(transfer, expected)) return { kind: "unknown", reason: "circle_transfer_mismatch" };
    if (transfer.status === FAILED_STATUS) return { kind: "failed", transfer };
    if (!ACCEPTED_STATUSES.has(transfer.status)) return { kind: "unknown", reason: "circle_transfer_status_unknown" };
    return { kind: "accepted", transfer };
  }
}
