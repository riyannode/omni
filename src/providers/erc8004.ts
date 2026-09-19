/**
 * ERC-8004 on-chain reader.
 *
 * Reads identity and reputation data from the ERC-8004 IdentityRegistry and
 * ReputationRegistry contracts. Production chains: Ethereum Mainnet (1) and
 * Base Mainnet (8453). Testnets available for development.
 *
 * Spec: https://eips.ethereum.org/EIPS/eip-8004 (Jan 2026)
 *
 * Design constraints:
 * - Read-only. No on-chain writes under any circumstances.
 * - No getClients() / unbounded array calls.
 * - Reputation scan uses bounded backward eth_getLogs chunks (NewFeedback /
 *   FeedbackRevoked events). ABI decoding via viem.
 * - getAgentWallet(agentId) — not getMetadata("agentWallet") — for wallet.
 * - DNS-pinned hardened fetch via node:https + node:dns/promises (no undici).
 * - Redirect-to-private attribution follows the caller-supplied targetUrl rules.
 */

import * as https from "node:https";
import * as dns from "node:dns/promises";
import {
  decodeEventLog,
  parseAbiItem,
  hexToBytes,
  bytesToBigInt,
  bytesToString,
  toHex,
} from "viem";
import type { AgentChainIdentityResult, AgentReputationSummary, AgentServiceObservation } from "../domain/risk.ts";

// ---------------------------------------------------------------------------
// Official ERC-8004 event topics (Jan 2026 spec)
// ---------------------------------------------------------------------------

// NewFeedback(uint256,address,uint64,int128,uint8,string,string,string,string,string,bytes32)
export const NEW_FEEDBACK_TOPIC = "0x6a4a61743519c9d648a14e6493f47dbe3ff1aa29e7785c96c8326a205e58febc";
// FeedbackRevoked(uint256,address,uint64)
export const FEEDBACK_REVOKED_TOPIC = "0x25156fd3288212246d8b008d5921fde376c71ed14ac2e072a506eb06fde6d09d";

// ---------------------------------------------------------------------------
// Chain configuration (data-driven)
// ---------------------------------------------------------------------------

export type Erc8004ChainConfig = {
  /** CAIP-2 chain reference, e.g. "eip155:1" */
  readonly chainRef: string;
  readonly chainId: number;
  readonly rpcUrl: string;
  readonly identityRegistry: `0x${string}`;
  readonly reputationRegistry: `0x${string}`;
  readonly validationRegistry?: `0x${string}`;
  readonly enabled: boolean;
  readonly deployment: "official" | "testnet" | "third-party";
  readonly source: string;
};

/**
 * Official ERC-8004 deployments verified from:
 * - https://eips.ethereum.org/EIPS/eip-8004
 * - https://github.com/questflowai/erc-8004-contracts
 * - https://github.com/ChaosChain/trustless-agents-erc-ri
 *
 * Production chains use canonical CREATE2 vanity addresses (same on all chains).
 * Testnets use separate vanity addresses.
 */
export const ERC8004_CHAINS: Readonly<Record<string, Erc8004ChainConfig>> = {
  "eip155:1": {
    chainRef: "eip155:1",
    chainId: 1,
    rpcUrl: "https://eth.llamarpc.com",
    identityRegistry: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
    reputationRegistry: "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63",
    enabled: true,
    deployment: "official",
    source: "https://eips.ethereum.org/EIPS/eip-8004",
  },
  "eip155:8453": {
    chainRef: "eip155:8453",
    chainId: 8453,
    rpcUrl: "https://mainnet.base.org",
    identityRegistry: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
    reputationRegistry: "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63",
    enabled: true,
    deployment: "official",
    source: "https://eips.ethereum.org/EIPS/eip-8004",
  },
} as const;

export const ERC8004_TESTNET_CHAINS: Readonly<Record<string, Erc8004ChainConfig>> = {
  "eip155:11155111": {
    chainRef: "eip155:11155111",
    chainId: 11155111,
    rpcUrl: "https://rpc.sepolia.org",
    identityRegistry: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
    reputationRegistry: "0x8004B663056A597Dffe9eCcC1965A193B7388713",
    enabled: true,
    deployment: "testnet",
    source: "https://github.com/ChaosChain/trustless-agents-erc-ri",
  },
} as const;

/** Resolve a CAIP-2 chain reference to its config. Returns undefined if unsupported. */
export function getChainConfig(chainRef: string): Erc8004ChainConfig | undefined {
  return ERC8004_CHAINS[chainRef] ?? ERC8004_TESTNET_CHAINS[chainRef];
}

/** All production chain configs (enabled only). */
export const ERC8004_PRODUCTION_CHAINS: readonly Erc8004ChainConfig[] = Object.values(ERC8004_CHAINS).filter(c => c.enabled);

// ---------------------------------------------------------------------------
// Private-IP CIDR guards (for redirect-to-private detection)
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

/** Check if an IPv4-mapped IPv6 address (::ffff:x.x.x.x) is private. */
function isPrivateIpv4MappedIpv6(ip: string): boolean {
  if (!ip.toLowerCase().startsWith("::ffff:")) return false;
  const ipv4Part = ip.slice(7);
  return isPrivateIpv4(ipv4Part);
}

async function hostnameResolvesToPrivate(hostname: string): Promise<boolean> {
  try {
    const [ipv4Results, ipv6Results] = await Promise.all([
      dns.resolve4(hostname).catch(() => [] as string[]),
      dns.resolve6(hostname).catch(() => [] as string[]),
    ]);
    const allIps = [...ipv4Results, ...ipv6Results];
    if (allIps.length === 0) return false;
    return allIps.every(ip => isPrivateIpv4(ip) || isPrivateIpv6(ip) || isPrivateIpv4MappedIpv6(ip));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// DNS-pinned hardened HTTPS GET (no undici, no new dependencies)
// ---------------------------------------------------------------------------

const MAX_REGISTRATION_BODY_BYTES = 256 * 1024; // 256 KiB cap

/** Fetches a URL via node:https with DNS pre-resolution to block SSRF. */
async function hardenedFetch(url: string, timeoutMs = 5000): Promise<{ status: number; body: string; finalUrl: string }> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new Error(`hardenedFetch: only https:// is supported (got ${parsed.protocol})`);
  }
  const hostname = parsed.hostname;
  // Resolve DNS before connecting; reject if all IPs are private.
  const addrs4 = await dns.resolve4(hostname).catch(() => [] as string[]);
  const addrs6 = await dns.resolve6(hostname).catch(() => [] as string[]);
  const allIps = [...addrs4, ...addrs6];
  if (allIps.length === 0) throw new Error(`hardenedFetch: DNS resolution failed for ${hostname}`);
  if (allIps.every(ip => isPrivateIpv4(ip) || isPrivateIpv6(ip) || isPrivateIpv4MappedIpv6(ip))) {
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
      // Follow at most one redirect; re-check DNS on redirect target.
      const location = res.headers.location;
      if ((res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) && location) {
        res.resume();
        // Return status 0 as sentinel for redirect; caller handles it.
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
  if (allIps.every(ip => isPrivateIpv4(ip) || isPrivateIpv6(ip) || isPrivateIpv4MappedIpv6(ip))) {
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
// ABI encoding helpers (minimal, viem used for decoding)
// ---------------------------------------------------------------------------

function encodeUint256(n: bigint | number): string {
  return BigInt(n).toString(16).padStart(64, "0");
}

function encodeAddress(addr: string): string {
  return addr.replace(/^0x/i, "").padStart(64, "0");
}

function decodeAddress(hex: string): string {
  return "0x" + hex.slice(-40);
}

function decodeUint256(hex: string): bigint {
  return BigInt("0x" + hex.padStart(64, "0").slice(0, 64));
}

function decodeString(data: string): string {
  // ABI-encoded string: offset (32 bytes) + length (32 bytes) + UTF-8 data
  const hex = data.replace(/^0x/i, "");
  if (hex.length < 128) return "";
  const length = parseInt(hex.slice(64, 128), 16);
  if (length === 0) return "";
  const bytes = Buffer.from(hex.slice(128, 128 + length * 2), "hex");
  return bytes.toString("utf8");
}

// Function selectors (keccak256 first 4 bytes, pre-computed)
const SEL = {
  // keccak256("ownerOf(uint256)") = 0x6352211e...
  ownerOf: "6352211e",
  // keccak256("getAgentWallet(uint256)") = 0x00339509...
  getAgentWallet: "00339509",
  // keccak256("tokenURI(uint256)") = 0xc87b56dd...
  tokenURI: "c87b56dd",
};

// ---------------------------------------------------------------------------
// Agent card JSON schema (minimal)
// ---------------------------------------------------------------------------

type AgentCardService = {
  type?: unknown;
  endpoint?: unknown;
  schema?: unknown;
};

type AgentCard = {
  name?: unknown;
  description?: unknown;
  services?: AgentCardService[];
  x402?: unknown;
  active?: unknown;
  registrations?: unknown;
  supportedTrust?: unknown;
};

function parseAgentCard(uri: string, json: unknown): { card: AgentCard; parseError?: string } {
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    return { card: {}, parseError: "agent card is not an object" };
  }
  void uri; // available for future provenance checking
  return { card: json as AgentCard };
}

function extractServices(card: AgentCard): AgentServiceObservation[] {
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
  const { chainId, rpcUrl, identityRegistry } = config;

  // ownerOf(agentId) — if the token does not exist the call reverts
  let ownerAddress: string | undefined;
  try {
    const callData = "0x" + SEL.ownerOf + encodeUint256(agentId);
    const result = await rpcPost(rpcUrl, "eth_call", [{ to: identityRegistry, data: callData }, "latest"]) as string;
    if (typeof result === "string" && result.length >= 42) {
      ownerAddress = decodeAddress(result.replace(/^0x/i, ""));
    }
  } catch (e) {
    // Check if this is a revert (token doesn't exist) vs RPC failure
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("revert") || msg.includes("execution reverted")) {
      return { chainId, registered: false };
    }
    // RPC/transport error — propagate as error
    return { chainId, registered: false, error: msg };
  }

  if (!ownerAddress || ownerAddress === "0x0000000000000000000000000000000000000000") {
    return { chainId, registered: false };
  }

  // getAgentWallet(agentId) — ERC-8004 specific
  let agentWallet: string | undefined;
  try {
    const callData = "0x" + SEL.getAgentWallet + encodeUint256(agentId);
    const result = await rpcPost(rpcUrl, "eth_call", [{ to: identityRegistry, data: callData }, "latest"]) as string;
    if (typeof result === "string" && result.length >= 42) {
      agentWallet = decodeAddress(result.replace(/^0x/i, ""));
      if (agentWallet === "0x0000000000000000000000000000000000000000") agentWallet = undefined;
    }
  } catch {
    // Not critical; continue without wallet
  }

  // tokenURI(agentId) → registrationUri
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
    ownerAddress,
    ...(agentWallet ? { agentWallet } : {}),
    ...(registrationUri ? { registrationUri } : {}),
  };
}

// ---------------------------------------------------------------------------
// ERC-8004 reputation reader (bounded eth_getLogs)
// ---------------------------------------------------------------------------

export const REPUTATION_CHUNK_SIZE = 5000n;
export const REPUTATION_DEFAULT_MAX_CHUNKS = 20;

/**
 * Decoded feedback entry. No universal positive/neutral/negative interpretation.
 * value + valueDecimals form a signed fixed-point number.
 * Policy determines direction/threshold per trusted reviewer + recognized tag.
 */
export type FeedbackEntry = {
  clientAddress: string;
  feedbackIndex: number;
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
  errors: string[];
};

async function getLatestBlock(rpcUrl: string): Promise<bigint> {
  const result = await rpcPost(rpcUrl, "eth_blockNumber", []) as string;
  return BigInt(result);
}

function padTopic(value: bigint): string {
  return "0x" + value.toString(16).padStart(64, "0");
}

// Decode NewFeedback event log using viem:
// topics[0] = event signature
// topics[1] = agentId (indexed uint256)
// topics[2] = clientAddress (indexed address)
// topics[3] = indexedTag1 (indexed string)
// data = ABI-encoded (uint64 feedbackIndex, int128 value, uint8 valueDecimals, string tag1, string tag2, string endpoint, string feedbackURI, bytes32 feedbackHash)
function decodeNewFeedback(log: { topics: string[]; data: string }): Omit<FeedbackEntry, "revoked"> | undefined {
  try {
    const clientAddress = "0x" + (log.topics[2] ?? "").slice(-40);
    const hex = (log.data ?? "").replace(/^0x/i, "");
    if (hex.length < 64) return undefined;

    // First 32 bytes: feedbackIndex (uint64, but padded to 32 bytes)
    const feedbackIndex = parseInt(hex.slice(0, 64), 16);
    // Next 32 bytes: value (int128)
    const valueHex = hex.slice(64, 128);
    const value = BigInt("0x" + valueHex);
    // Next 32 bytes: valueDecimals (uint8)
    const valueDecimals = parseInt(hex.slice(128, 192), 16);

    // Remaining data: offset to tag1 string, then tag1, tag2, endpoint, feedbackURI, feedbackHash
    // For simplicity, decode strings manually from the remaining data
    let offset = 192;
    const tag1Offset = parseInt(hex.slice(offset, offset + 64), 16) * 2;
    offset += 64;
    const tag2Offset = parseInt(hex.slice(offset, offset + 64), 16) * 2;
    offset += 64;
    const endpointOffset = parseInt(hex.slice(offset, offset + 64), 16) * 2;
    offset += 64;
    const feedbackURIOffset = parseInt(hex.slice(offset, offset + 64), 16) * 2;
    offset += 64;
    const feedbackHash = "0x" + hex.slice(offset, offset + 64);

    const tag1 = decodeAbiString(hex, tag1Offset);
    const tag2 = decodeAbiString(hex, tag2Offset);
    const endpoint = decodeAbiString(hex, endpointOffset);
    const feedbackURI = decodeAbiString(hex, feedbackURIOffset);

    return {
      clientAddress,
      feedbackIndex,
      value,
      valueDecimals,
      tag1,
      tag2,
      endpoint,
      feedbackURI,
      feedbackHash,
    };
  } catch {
    return undefined;
  }
}

function decodeAbiString(hex: string, offset: number): string {
  try {
    if (offset + 64 > hex.length) return "";
    const length = parseInt(hex.slice(offset, offset + 64), 16);
    if (length === 0) return "";
    const bytes = Buffer.from(hex.slice(offset + 64, offset + 64 + length * 2), "hex");
    return bytes.toString("utf8");
  } catch {
    return "";
  }
}

// Decode FeedbackRevoked event log:
// topics[0] = event signature
// topics[1] = agentId (indexed uint256)
// topics[2] = clientAddress (indexed address)
// topics[3] = feedbackIndex (indexed uint64)
function decodeRevokedKey(log: { topics: string[] }): { clientAddress: string; feedbackIndex: number } | undefined {
  try {
    const clientAddress = "0x" + (log.topics[2] ?? "").slice(-40);
    const feedbackIndex = parseInt((log.topics[3] ?? "").replace(/^0x/i, "") || "0", 16);
    return { clientAddress, feedbackIndex };
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
  const { rpcUrl, reputationRegistry } = config;
  const errors: string[] = [];

  let latestBlock: bigint;
  try {
    latestBlock = await getLatestBlock(rpcUrl);
  } catch (e) {
    return {
      feedback: [],
      blocksScanned: 0n,
      historyCoverage: "partial",
      errors: [`eth_blockNumber failed: ${e instanceof Error ? e.message : String(e)}`],
    };
  }

  const agentIdPaddedTopic = padTopic(agentId);
  const newFeedbackTopic = NEW_FEEDBACK_TOPIC;
  const feedbackRevokedTopic = FEEDBACK_REVOKED_TOPIC;

  // Key: (clientAddress, feedbackIndex) — stable per reviewer per feedback
  const feedbackMap = new Map<string, FeedbackEntry>();
  let currentBlock = latestBlock;
  let chunksScanned = 0;

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

    // Apply NewFeedback entries (newer wins on key=(clientAddress, feedbackIndex))
    for (const log of newLogs) {
      const decoded = decodeNewFeedback(log);
      if (!decoded) continue;
      const clientAddress = decoded.clientAddress.toLowerCase();
      if (trustedReviewers !== null && !trustedReviewers.has(clientAddress)) continue;
      const key = `${clientAddress}:${decoded.feedbackIndex}`;
      feedbackMap.set(key, {
        ...decoded,
        clientAddress,
        revoked: false,
      });
    }

    // Apply revocations by exact (clientAddress, feedbackIndex)
    for (const log of revokedLogs) {
      const revoked = decodeRevokedKey(log);
      if (!revoked) continue;
      const clientAddress = revoked.clientAddress.toLowerCase();
      const key = `${clientAddress}:${revoked.feedbackIndex}`;
      const entry = feedbackMap.get(key);
      if (entry) feedbackMap.set(key, { ...entry, revoked: true });
    }

    if (fromBlock === 0n) break;
    currentBlock = fromBlock - 1n;
  }

  const blocksScanned = latestBlock - currentBlock;
  const historyCoverage: "complete" | "partial" = currentBlock === 0n ? "complete" : "partial";

  return {
    feedback: [...feedbackMap.values()],
    blocksScanned,
    historyCoverage,
    errors,
  };
}

// ---------------------------------------------------------------------------
// Agent card fetcher (via registrationUri)
// ---------------------------------------------------------------------------

export type AgentCardResult = {
  card?: AgentCard;
  rawUri?: string;
  error?: string;
};

export async function fetchAgentCard(registrationUri: string): Promise<AgentCardResult> {
  if (!registrationUri) return { error: "no registration URI" };

  try {
    // data:application/json;base64 URI
    if (registrationUri.startsWith("data:application/json;base64,")) {
      const b64 = registrationUri.slice("data:application/json;base64,".length);
      const json = JSON.parse(Buffer.from(b64, "base64").toString("utf8")) as unknown;
      const { card, parseError } = parseAgentCard(registrationUri, json);
      return parseError ? { rawUri: registrationUri, error: parseError } : { card, rawUri: registrationUri };
    }

    const parsed = new URL(registrationUri);

    // IPFS URIs: convert to https gateway fetch
    if (parsed.protocol === "ipfs:") {
      // URL parsing places CID in hostname for ipfs://<CID>/...
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
    // Handle one redirect
    if (result.status === 0 && result.body) {
      const redirectUrl = result.body;
      // Re-check redirect target for SSRF
      const redirectParsed = new URL(redirectUrl);
      if (redirectParsed.protocol !== "https:") {
        return { rawUri, error: `redirect to non-HTTPS protocol rejected: ${redirectParsed.protocol}` };
      }
      const redirected = await hardenedFetch(redirectUrl, 5000);
      if (redirected.status !== 200) {
        return { rawUri, error: `agent card HTTP ${redirected.status} after redirect` };
      }
      const json = JSON.parse(redirected.body) as unknown;
      const { card, parseError } = parseAgentCard(rawUri, json);
      return parseError ? { rawUri, error: parseError } : { card, rawUri };
    }
    if (result.status !== 200) return { rawUri, error: `agent card HTTP ${result.status}` };
    const json = JSON.parse(result.body) as unknown;
    const { card, parseError } = parseAgentCard(rawUri, json);
    return parseError ? { rawUri, error: parseError } : { card, rawUri };
  } catch (e) {
    return { rawUri, error: e instanceof Error ? e.message : String(e) };
  }
}

// ---------------------------------------------------------------------------
// Redirect-to-private probe
// ---------------------------------------------------------------------------

/**
 * Probes a target URL to detect redirect to a private IP.
 * Returns true only if the final redirect destination resolves to a private address.
 * Used only when targetUrl was caller-supplied AND matches an advertised service endpoint.
 */
export async function probeTargetUrlRedirectsToPrivate(targetUrl: string): Promise<{ redirectsToPrivate: boolean; error?: string }> {
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== "https:") return { redirectsToPrivate: false };

    const result = await hardenedFetch(targetUrl, 5000).catch(e => {
      // hardenedFetch itself rejects on private IP; that IS the signal
      if (e instanceof Error && e.message.includes("SSRF rejected")) {
        return { status: 0, body: "", finalUrl: targetUrl, ssrfRejected: true } as { status: number; body: string; finalUrl: string; ssrfRejected?: boolean };
      }
      throw e;
    });

    if ((result as { ssrfRejected?: boolean }).ssrfRejected) return { redirectsToPrivate: true };

    // status 0 means redirect; check redirect target
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

// Re-export types needed by services.ts
export type { AgentCard, AgentCardService };
export { extractServices };
