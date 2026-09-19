/**
 * ERC-8004 on-chain reader.
 *
 * Reads identity and reputation data from the ERC-8004 IdentityRegistry and
 * ReputationRegistry contracts.
 *
 * Spec: https://eips.ethereum.org/EIPS/eip-8004 (Jan 2026)
 * Official contracts: https://github.com/erc-8004/erc-8004-contracts
 *
 * Design constraints:
 * - Read-only. No on-chain writes under any circumstances.
 * - Reputation scan uses bounded backward eth_getLogs chunks (NewFeedback /
 *   FeedbackRevoked events). ABI decoding via viem decodeEventLog.
 * - DNS-pinned hardened fetch via node:https + node:dns/promises (no undici).
 */

import * as https from "node:https";
import * as dns from "node:dns/promises";
import { decodeEventLog, type AbiEvent } from "viem";
import type { AgentChainIdentityResult, AgentIdentityStatus, AgentReputationSummary, AgentServiceObservation } from "../domain/risk.ts";

// ---------------------------------------------------------------------------
// Official ERC-8004 event definitions (from github.com/erc-8004/erc-8004-contracts)
// ---------------------------------------------------------------------------

const NEW_FEEDBACK_EVENT = {
  type: "event",
  name: "NewFeedback",
  inputs: [
    { name: "agentId", type: "uint256", indexed: true },
    { name: "clientAddress", type: "address", indexed: true },
    { name: "feedbackIndex", type: "uint64", indexed: false },
    { name: "value", type: "int128", indexed: false },
    { name: "valueDecimals", type: "uint8", indexed: false },
    { name: "indexedTag1", type: "string", indexed: true },
    { name: "tag1", type: "string", indexed: false },
    { name: "tag2", type: "string", indexed: false },
    { name: "endpoint", type: "string", indexed: false },
    { name: "feedbackURI", type: "string", indexed: false },
    { name: "feedbackHash", type: "bytes32", indexed: false },
  ],
  anonymous: false,
} as const satisfies AbiEvent;

const FEEDBACK_REVOKED_EVENT = {
  type: "event",
  name: "FeedbackRevoked",
  inputs: [
    { name: "agentId", type: "uint256", indexed: true },
    { name: "clientAddress", type: "address", indexed: true },
    { name: "feedbackIndex", type: "uint64", indexed: true },
  ],
  anonymous: false,
} as const satisfies AbiEvent;

// Computed topic hashes (verified against official ABI)
export const NEW_FEEDBACK_TOPIC = "0x6a4a61743519c9d648a14e6493f47dbe3ff1aa29e7785c96c8326a205e58febc";
export const FEEDBACK_REVOKED_TOPIC = "0x25156fd3288212246d8b008d5921fde376c71ed14ac2e072a506eb06fde6d09d";

// ---------------------------------------------------------------------------
// Chain configuration (data-driven)
// ---------------------------------------------------------------------------

export type Erc8004ChainConfig = {
  readonly chainRef: string;
  readonly chainId: number;
  readonly identityRegistry: `0x${string}`;
  readonly reputationRegistry: `0x${string}`;
  readonly validationRegistry?: `0x${string}`;
  readonly enabled: boolean;
  readonly deployment: "official" | "testnet" | "third-party";
  readonly source: string;
};

/**
 * Official ERC-8004 deployments verified from:
 * - https://github.com/erc-8004/erc-8004-contracts
 * - https://eips.ethereum.org/EIPS/eip-8004
 *
 * RPC URLs are operator-configurable via env: ERC8004_RPC_OVERRIDE_<chainId>
 */
export const ERC8004_CHAINS: Readonly<Record<string, Erc8004ChainConfig>> = {
  "eip155:1": {
    chainRef: "eip155:1",
    chainId: 1,
    identityRegistry: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
    reputationRegistry: "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63",
    enabled: true,
    deployment: "official",
    source: "https://github.com/erc-8004/erc-8004-contracts",
  },
  "eip155:8453": {
    chainRef: "eip155:8453",
    chainId: 8453,
    identityRegistry: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
    reputationRegistry: "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63",
    enabled: true,
    deployment: "official",
    source: "https://github.com/erc-8004/erc-8004-contracts",
  },
} as const;

export const ERC8004_TESTNET_CHAINS: Readonly<Record<string, Erc8004ChainConfig>> = {
  "eip155:11155111": {
    chainRef: "eip155:11155111",
    chainId: 11155111,
    identityRegistry: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
    reputationRegistry: "0x8004B663056A597Dffe9eCcC1965A193B7388713",
    enabled: true,
    deployment: "testnet",
    source: "https://github.com/erc-8004/erc-8004-contracts",
  },
} as const;

export function getChainConfig(chainRef: string): Erc8004ChainConfig | undefined {
  return ERC8004_CHAINS[chainRef] ?? ERC8004_TESTNET_CHAINS[chainRef];
}

export function getChainRpcUrl(config: Erc8004ChainConfig): string {
  const override = process.env[`ERC8004_RPC_OVERRIDE_${config.chainId}`];
  if (override) return override;
  if (config.chainId === 1) return "https://eth.llamarpc.com";
  if (config.chainId === 8453) return "https://mainnet.base.org";
  if (config.chainId === 11155111) return "https://rpc.sepolia.org";
  throw new Error(`No RPC configured for chain ${config.chainId}`);
}

export const ERC8004_PRODUCTION_CHAINS: readonly Erc8004ChainConfig[] = Object.values(ERC8004_CHAINS).filter(c => c.enabled);

// ---------------------------------------------------------------------------
// Private-IP CIDR guards
// ---------------------------------------------------------------------------

const PRIVATE_RANGES: Array<{ start: bigint; end: bigint }> = (function () {
  function ip4ToBigInt(ip: string): bigint {
    return ip.split(".").reduce((acc, part) => (acc << 8n) | BigInt(parseInt(part, 10)), 0n);
  }
  function range(cidr: string): { start: bigint; end: bigint } {
    const [base, bits] = cidr.split("/") as [string, string];
    const mask = ~((1n << BigInt(32 - parseInt(bits, 10))) - 1n) & 0xffffffffn;
    const start = ip4ToBigInt(base) & mask;
    const end = start | (~mask & 0xffffffffn);
    return { start, end };
  }
  return [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "100.64.0.0/10",
  ].map(range);
})();

function isPrivateIpv4(ip: string): boolean {
  try {
    const n = ip.split(".").reduce((acc, p) => (acc << 8n) | BigInt(parseInt(p, 10)), 0n);
    return PRIVATE_RANGES.some(r => n >= r.start && n <= r.end);
  } catch {
    return false;
  }
}

function isPrivateIpv6(ip: string): boolean {
  return (
    ip === "::1" ||
    ip.startsWith("fe80:") || ip.startsWith("FE80:") ||
    ip.startsWith("fc") || ip.startsWith("FC") ||
    ip.startsWith("fd") || ip.startsWith("FD") ||
    ip === "::"
  );
}

function isPrivateIpv4MappedIpv6(ip: string): boolean {
  if (!ip.toLowerCase().startsWith("::ffff:")) return false;
  const ipv4Part = ip.slice(7);
  return isPrivateIpv4(ipv4Part);
}

export function isPrivateIp(ip: string): boolean {
  return isPrivateIpv4(ip) || isPrivateIpv6(ip) || isPrivateIpv4MappedIpv6(ip);
}

/**
 * SAFE POLICY: reject if ANY resolved address is private.
 */
export async function hostnameResolvesToPrivate(hostname: string): Promise<boolean> {
  try {
    const [ipv4Results, ipv6Results] = await Promise.all([
      dns.resolve4(hostname).catch(() => [] as string[]),
      dns.resolve6(hostname).catch(() => [] as string[]),
    ]);
    const allIps = [...ipv4Results, ...ipv6Results];
    if (allIps.length === 0) return true;
    return allIps.some(ip => isPrivateIp(ip));
  } catch {
    return true;
  }
}

// ---------------------------------------------------------------------------
// DNS-pinned hardened HTTPS GET
// ---------------------------------------------------------------------------

const MAX_REGISTRATION_BODY_BYTES = 256 * 1024;

async function hardenedFetch(url: string, timeoutMs = 5000): Promise<{ status: number; body: string; finalUrl: string }> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new Error(`hardenedFetch: only https:// is supported (got ${parsed.protocol})`);
  }
  const hostname = parsed.hostname;
  const addrs4 = await dns.resolve4(hostname).catch(() => [] as string[]);
  const addrs6 = await dns.resolve6(hostname).catch(() => [] as string[]);
  const allIps = [...addrs4, ...addrs6];
  if (allIps.length === 0) throw new Error(`hardenedFetch: DNS resolution failed for ${hostname}`);
  if (allIps.some(ip => isPrivateIp(ip))) {
    throw new Error(`hardenedFetch: ${hostname} resolves to a private address (SSRF rejected)`);
  }
  const pinnedIp = addrs4[0] ?? addrs6[0]!;

  return new Promise((resolve, reject) => {
    const options: https.RequestOptions = {
      hostname: pinnedIp,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: "GET",
      headers: {
        "Host": hostname,
        "User-Agent": "OMNI-agent-risk/1 (+https://api.askomni.xyz)",
        "Accept": "application/json",
      },
      timeout: timeoutMs,
    };
    const req = https.request(options, (res) => {
      const location = res.headers.location;
      if ((res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) && location) {
        res.resume();
        resolve({ status: 0, body: location, finalUrl: location });
        return;
      }
      const chunks: Buffer[] = [];
      let totalBytes = 0;
      res.on("data", (chunk: Buffer) => {
        totalBytes += chunk.byteLength;
        if (totalBytes > MAX_REGISTRATION_BODY_BYTES) {
          req.destroy();
          reject(new Error(`hardenedFetch: response body exceeds ${MAX_REGISTRATION_BODY_BYTES} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8"), finalUrl: url }));
      res.on("error", reject);
    });
    req.on("timeout", () => { req.destroy(); reject(new Error(`hardenedFetch: request timeout for ${url}`)); });
    req.on("error", reject);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Low-level JSON-RPC helpers
// ---------------------------------------------------------------------------

type JsonRpcResponse = { id: number; jsonrpc: string; result?: unknown; error?: { code: number; message: string } };

async function rpcPost(rpcUrl: string, method: string, params: unknown[], timeoutMs = 8000): Promise<unknown> {
  const hostname = new URL(rpcUrl).hostname;
  const addrs4 = await dns.resolve4(hostname).catch(() => [] as string[]);
  const addrs6 = await dns.resolve6(hostname).catch(() => [] as string[]);
  const allIps = [...addrs4, ...addrs6];
  if (allIps.length === 0) throw new Error(`rpcPost: DNS resolution failed for ${hostname}`);
  if (allIps.some(ip => isPrivateIp(ip))) {
    throw new Error(`rpcPost: RPC host ${hostname} resolves to private address`);
  }
  const pinnedIp = addrs4[0] ?? addrs6[0]!;
  const parsed = new URL(rpcUrl);
  const bodyStr = JSON.stringify({ id: 1, jsonrpc: "2.0", method, params });

  return new Promise((resolve, reject) => {
    const options: https.RequestOptions = {
      hostname: pinnedIp,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: "POST",
      headers: {
        "Host": hostname,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(bodyStr),
        "User-Agent": "OMNI-agent-risk/1 (+https://api.askomni.xyz)",
      },
      timeout: timeoutMs,
    };
    const req = https.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        try {
          const json = JSON.parse(Buffer.concat(chunks).toString("utf8")) as JsonRpcResponse;
          if (json.error) reject(new Error(`RPC error ${json.error.code}: ${json.error.message}`));
          else resolve(json.result);
        } catch (e) {
          reject(new Error(`rpcPost: invalid JSON response: ${e instanceof Error ? e.message : String(e)}`));
        }
      });
      res.on("error", reject);
    });
    req.on("timeout", () => { req.destroy(); reject(new Error(`rpcPost: timeout calling ${method} on ${rpcUrl}`)); });
    req.on("error", reject);
    req.write(bodyStr);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// ABI encoding helpers
// ---------------------------------------------------------------------------

function encodeUint256(n: bigint | number): string {
  return BigInt(n).toString(16).padStart(64, "0");
}

function decodeAddress(hex: string): string {
  return "0x" + hex.slice(-40);
}

function decodeString(data: string): string {
  const hex = data.replace(/^0x/i, "");
  if (hex.length < 128) return "";
  const length = parseInt(hex.slice(64, 128), 16);
  if (length === 0) return "";
  const bytes = Buffer.from(hex.slice(128, 128 + length * 2), "hex");
  return bytes.toString("utf8");
}

const SEL = {
  ownerOf: "6352211e",
  getAgentWallet: "00339509",
  tokenURI: "c87b56dd",
};

// ---------------------------------------------------------------------------
// Agent card JSON schema
// ---------------------------------------------------------------------------

export type AgentCardService = {
  type?: unknown;
  name?: unknown;
  endpoint?: unknown;
  schema?: unknown;
};

export type AgentCard = {
  type?: unknown;
  name?: unknown;
  description?: unknown;
  services?: AgentCardService[];
  x402Support?: unknown;
  active?: unknown;
  registrations?: unknown;
  supportedTrust?: unknown;
};

export type AgentCardValidationResult = {
  card?: AgentCard;
  parseError?: string;
  structuralError?: string;
  selfReferenceMatch?: boolean;
};

function validateAgentCardStructure(card: AgentCard): string | undefined {
  if (card.services !== undefined) {
    if (!Array.isArray(card.services)) return "services must be an array";
    for (const svc of card.services) {
      if (typeof svc !== "object" || svc === null) return "service must be an object";
      const s = svc as Record<string, unknown>;
      if (s.endpoint !== undefined && typeof s.endpoint !== "string") return "service endpoint must be a string";
      if (s.name !== undefined && typeof s.name !== "string") return "service name must be a string";
    }
  }
  return undefined;
}

export function parseAgentCard(uri: string, json: unknown): AgentCardValidationResult {
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    return { parseError: "agent card is not an object" };
  }
  const card = json as AgentCard;
  const structuralError = validateAgentCardStructure(card);
  return structuralError ? { parseError: structuralError, structuralError } : { card };
}

export function extractServices(card: AgentCard): AgentServiceObservation[] {
  if (!Array.isArray(card.services)) return [];
  return card.services.flatMap(service => {
    if (typeof service !== "object" || service === null) return [];
    const obs: AgentServiceObservation = { type: typeof service.type === "string" ? service.type : "unknown" };
    if (typeof service.endpoint === "string") obs.endpoint = service.endpoint;
    if (typeof service.schema === "string") obs.schema = service.schema;
    return [obs];
  });
}

// ---------------------------------------------------------------------------
// ERC-8004 identity reader
// ---------------------------------------------------------------------------

export async function readAgentIdentity(
  config: Erc8004ChainConfig,
  agentId: bigint
): Promise<AgentChainIdentityResult> {
  const { chainId, identityRegistry } = config;
  const rpcUrl = getChainRpcUrl(config);

  let ownerAddress: string | undefined;
  try {
    const callData = "0x" + SEL.ownerOf + encodeUint256(agentId);
    const result = await rpcPost(rpcUrl, "eth_call", [{ to: identityRegistry, data: callData }, "latest"]) as string;
    if (typeof result === "string" && result.length >= 42) {
      ownerAddress = decodeAddress(result.replace(/^0x/i, ""));
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("revert") || msg.includes("execution reverted")) {
      return { chainId, registered: false, status: "NOT_REGISTERED" as const, ownerAddress: undefined, agentWallet: undefined, registrationUri: undefined, error: undefined };
    }
    return { chainId, registered: false, status: "UNAVAILABLE" as const, ownerAddress: undefined, agentWallet: undefined, registrationUri: undefined, error: msg };
  }

  if (!ownerAddress || ownerAddress === "0x0000000000000000000000000000000000000000") {
    return { chainId, registered: false, status: "NOT_REGISTERED" as const, ownerAddress: undefined, agentWallet: undefined, registrationUri: undefined, error: undefined };
  }

  let agentWallet: string | undefined;
  try {
    const callData = "0x" + SEL.getAgentWallet + encodeUint256(agentId);
    const result = await rpcPost(rpcUrl, "eth_call", [{ to: identityRegistry, data: callData }, "latest"]) as string;
    if (typeof result === "string" && result.length >= 42) {
      agentWallet = decodeAddress(result.replace(/^0x/i, ""));
      if (agentWallet === "0x0000000000000000000000000000000000000000") agentWallet = undefined;
    }
  } catch {
    // Not critical
  }

  let registrationUri: string | undefined;
  try {
    const callData = "0x" + SEL.tokenURI + encodeUint256(agentId);
    const result = await rpcPost(rpcUrl, "eth_call", [{ to: identityRegistry, data: callData }, "latest"]) as string;
    if (typeof result === "string" && result.length > 2) {
      registrationUri = decodeString(result);
    }
  } catch {
    // Not critical
  }

  return {
    chainId,
    registered: true,
    status: "REGISTERED" as const,
    ownerAddress,
    agentWallet: agentWallet ?? undefined,
    registrationUri: registrationUri ?? undefined,
    error: undefined,
  };
}

// ---------------------------------------------------------------------------
// ERC-8004 reputation reader
// ---------------------------------------------------------------------------

export const REPUTATION_CHUNK_SIZE = 5000n;
export const REPUTATION_DEFAULT_MAX_CHUNKS = 20;
export const MAX_FEEDBACK_EVENTS = 1000;

export type FeedbackEntry = {
  clientAddress: string;
  feedbackIndex: bigint;
  value: bigint;
  valueDecimals: number;
  tag1: string;
  tag2: string;
  endpoint: string;
  feedbackURI: string;
  feedbackHash: string;
  revoked: boolean;
};

export type ReputationScanResult = {
  feedback: FeedbackEntry[];
  blocksScanned: bigint;
  historyCoverage: "complete" | "partial";
  truncated: boolean;
  totalEventsObserved: number;
  errors: string[];
};

async function getLatestBlock(rpcUrl: string): Promise<bigint> {
  const result = await rpcPost(rpcUrl, "eth_blockNumber", []) as string;
  return BigInt(result);
}

function padTopic(value: bigint): string {
  return "0x" + value.toString(16).padStart(64, "0");
}

function decodeNewFeedback(log: { topics: string[]; data: string }): Omit<FeedbackEntry, "revoked"> | undefined {
  try {
    const decoded = decodeEventLog({
      abi: [NEW_FEEDBACK_EVENT],
      data: log.data as `0x${string}`,
      topics: log.topics as [`0x${string}`, ...`0x${string}`[]],
    });
    const args = decoded.args as {
      agentId: bigint;
      clientAddress: string;
      feedbackIndex: bigint;
      value: bigint;
      valueDecimals: number;
      indexedTag1: string;
      tag1: string;
      tag2: string;
      endpoint: string;
      feedbackURI: string;
      feedbackHash: string;
    };
    return {
      clientAddress: args.clientAddress,
      feedbackIndex: args.feedbackIndex,
      value: args.value,
      valueDecimals: args.valueDecimals,
      tag1: args.tag1,
      tag2: args.tag2,
      endpoint: args.endpoint,
      feedbackURI: args.feedbackURI,
      feedbackHash: args.feedbackHash,
    };
  } catch {
    return undefined;
  }
}

function decodeRevokedKey(log: { topics: string[] }): { clientAddress: string; feedbackIndex: bigint } | undefined {
  try {
    const decoded = decodeEventLog({
      abi: [FEEDBACK_REVOKED_EVENT],
      data: "0x" as `0x${string}`,
      topics: log.topics as [`0x${string}`, ...`0x${string}`[]],
    });
    const args = decoded.args as {
      agentId: bigint;
      clientAddress: string;
      feedbackIndex: bigint;
    };
    return { clientAddress: args.clientAddress, feedbackIndex: args.feedbackIndex };
  } catch {
    return undefined;
  }
}

type EthLog = { topics: string[]; data: string; blockNumber?: string };

export async function scanAgentReputation(
  config: Erc8004ChainConfig,
  agentId: bigint,
  trustedReviewers: Set<string> | null,
  maxChunks = REPUTATION_DEFAULT_MAX_CHUNKS
): Promise<ReputationScanResult> {
  const { reputationRegistry } = config;
  const rpcUrl = getChainRpcUrl(config);
  const errors: string[] = [];

  let latestBlock: bigint;
  try {
    latestBlock = await getLatestBlock(rpcUrl);
  } catch (e) {
    return {
      feedback: [],
      blocksScanned: 0n,
      historyCoverage: "partial",
      truncated: false,
      totalEventsObserved: 0,
      errors: [`eth_blockNumber failed: ${e instanceof Error ? e.message : String(e)}`],
    };
  }

  const agentIdPaddedTopic = padTopic(agentId);
  const newFeedbackTopic = NEW_FEEDBACK_TOPIC;
  const feedbackRevokedTopic = FEEDBACK_REVOKED_TOPIC;

  const feedbackMap = new Map<string, FeedbackEntry>();
  const revokedKeys = new Set<string>();
  let currentBlock = latestBlock;
  let chunksScanned = 0;
  let totalEventsObserved = 0;
  let truncated = false;

  while (chunksScanned < maxChunks && currentBlock > 0n) {
    const fromBlock = currentBlock > REPUTATION_CHUNK_SIZE ? currentBlock - REPUTATION_CHUNK_SIZE + 1n : 0n;
    const chunkLabel = `blocks ${fromBlock}..${currentBlock}`;
    chunksScanned++;

    let newLogs: EthLog[] = [];
    let revokedLogs: EthLog[] = [];

    try {
      newLogs = (await rpcPost(rpcUrl, "eth_getLogs", [{
        address: reputationRegistry,
        topics: [newFeedbackTopic, agentIdPaddedTopic],
        fromBlock: "0x" + fromBlock.toString(16),
        toBlock: "0x" + currentBlock.toString(16),
      }]) ?? []) as EthLog[];
    } catch (e) {
      errors.push(`eth_getLogs(NewFeedback) ${chunkLabel}: ${e instanceof Error ? e.message : String(e)}`);
    }

    try {
      revokedLogs = (await rpcPost(rpcUrl, "eth_getLogs", [{
        address: reputationRegistry,
        topics: [feedbackRevokedTopic, agentIdPaddedTopic],
        fromBlock: "0x" + fromBlock.toString(16),
        toBlock: "0x" + currentBlock.toString(16),
      }]) ?? []) as EthLog[];
    } catch (e) {
      errors.push(`eth_getLogs(FeedbackRevoked) ${chunkLabel}: ${e instanceof Error ? e.message : String(e)}`);
    }

    totalEventsObserved += newLogs.length + revokedLogs.length;

    if (totalEventsObserved > MAX_FEEDBACK_EVENTS) {
      truncated = true;
      errors.push(`feedback event limit reached: ${totalEventsObserved} > ${MAX_FEEDBACK_EVENTS}`);
      break;
    }

    for (const log of revokedLogs) {
      const revoked = decodeRevokedKey(log);
      if (!revoked) continue;
      const clientAddress = revoked.clientAddress.toLowerCase();
      const key = `${clientAddress}:${revoked.feedbackIndex.toString()}`;
      revokedKeys.add(key);
    }

    for (const log of newLogs) {
      const decoded = decodeNewFeedback(log);
      if (!decoded) continue;
      const clientAddress = decoded.clientAddress.toLowerCase();
      if (trustedReviewers !== null && !trustedReviewers.has(clientAddress)) continue;
      const key = `${clientAddress}:${decoded.feedbackIndex.toString()}`;
      feedbackMap.set(key, {
        ...decoded,
        clientAddress,
        revoked: revokedKeys.has(key),
      });
    }

    for (const [key, entry] of feedbackMap) {
      if (revokedKeys.has(key) && !entry.revoked) {
        feedbackMap.set(key, { ...entry, revoked: true });
      }
    }

    if (fromBlock === 0n) break;
    currentBlock = fromBlock - 1n;
  }

  const blocksScanned = latestBlock - currentBlock;
  const historyCoverage: "complete" | "partial" = currentBlock === 0n && !truncated ? "complete" : "partial";

  return {
    feedback: [...feedbackMap.values()],
    blocksScanned,
    historyCoverage,
    truncated,
    totalEventsObserved,
    errors,
  };
}

// ---------------------------------------------------------------------------
// Agent card fetcher
// ---------------------------------------------------------------------------

export type AgentCardResult = {
  card?: AgentCard;
  rawUri?: string;
  error?: string;
  selfReferenceMatch?: boolean;
};

export async function fetchAgentCard(registrationUri: string): Promise<AgentCardResult> {
  if (!registrationUri) return { error: "no registration URI" };

  try {
    if (registrationUri.startsWith("data:application/json;base64,")) {
      const b64 = registrationUri.slice("data:application/json;base64,".length);
      if (b64.length > MAX_REGISTRATION_BODY_BYTES) {
        return { rawUri: registrationUri, error: `data URI payload exceeds ${MAX_REGISTRATION_BODY_BYTES} bytes` };
      }
      const decoded = Buffer.from(b64, "base64");
      if (decoded.length > MAX_REGISTRATION_BODY_BYTES) {
        return { rawUri: registrationUri, error: `decoded data URI exceeds ${MAX_REGISTRATION_BODY_BYTES} bytes` };
      }
      const json = JSON.parse(decoded.toString("utf8")) as unknown;
      const parsed = parseAgentCard(registrationUri, json);
      if (parsed.parseError) return { rawUri: registrationUri, error: parsed.parseError };
      return { card: parsed.card, rawUri: registrationUri };
    }

    const parsed = new URL(registrationUri);

    if (parsed.protocol === "ipfs:") {
      const cid = parsed.hostname || parsed.pathname.replace(/^\//, "");
      if (!cid) return { rawUri: registrationUri, error: "IPFS URI has no CID" };
      const gatewayUrl = `https://ipfs.io/ipfs/${cid}${parsed.pathname !== "/" ? parsed.pathname : ""}${parsed.search}`;
      return fetchAgentCardFromHttps(gatewayUrl, registrationUri);
    }

    if (parsed.protocol === "https:") {
      return fetchAgentCardFromHttps(registrationUri, registrationUri);
    }

    return { rawUri: registrationUri, error: `unsupported URI scheme: ${parsed.protocol}` };
  } catch (e) {
    return { rawUri: registrationUri, error: `invalid registration URI: ${e instanceof Error ? e.message : String(e)}` };
  }
}

async function fetchAgentCardFromHttps(url: string, rawUri: string): Promise<AgentCardResult> {
  try {
    const result = await hardenedFetch(url, 6000);
    if (result.status === 0 && result.body) {
      const redirectUrl = result.body;
      const redirectParsed = new URL(redirectUrl);
      if (redirectParsed.protocol !== "https:") {
        return { rawUri, error: `redirect to non-HTTPS protocol rejected: ${redirectParsed.protocol}` };
      }
      const redirected = await hardenedFetch(redirectUrl, 5000);
      if (redirected.status !== 200) {
        return { rawUri, error: `agent card HTTP ${redirected.status} after redirect` };
      }
      const json = JSON.parse(redirected.body) as unknown;
      const parsed = parseAgentCard(rawUri, json);
      if (parsed.parseError) return { rawUri, error: parsed.parseError };
      return { card: parsed.card, rawUri };
    }
    if (result.status !== 200) return { rawUri, error: `agent card HTTP ${result.status}` };
    const json = JSON.parse(result.body) as unknown;
    const parsed = parseAgentCard(rawUri, json);
    if (parsed.parseError) return { rawUri, error: parsed.parseError };
    return { card: parsed.card, rawUri };
  } catch (e) {
    return { rawUri, error: e instanceof Error ? e.message : String(e) };
  }
}

// ---------------------------------------------------------------------------
// Redirect-to-private probe
// ---------------------------------------------------------------------------

export async function probeTargetUrlRedirectsToPrivate(targetUrl: string): Promise<{ redirectsToPrivate: boolean; error?: string }> {
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== "https:") return { redirectsToPrivate: false };

    const result = await hardenedFetch(targetUrl, 5000).catch(e => {
      if (e instanceof Error && e.message.includes("SSRF rejected")) {
        return { status: 0, body: "", finalUrl: targetUrl, ssrfRejected: true } as { status: number; body: string; finalUrl: string; ssrfRejected?: boolean };
      }
      throw e;
    });

    if ((result as { ssrfRejected?: boolean }).ssrfRejected) return { redirectsToPrivate: true };

    if (result.status === 0 && result.body) {
      const redirectHostname = new URL(result.body).hostname;
      const isPrivate = await hostnameResolvesToPrivate(redirectHostname);
      return { redirectsToPrivate: isPrivate };
    }

    return { redirectsToPrivate: false };
  } catch (e) {
    return { redirectsToPrivate: false, error: e instanceof Error ? e.message : String(e) };
  }
}
