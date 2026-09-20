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
import * as net from "node:net";
import type { ClientRequest, IncomingMessage } from "node:http";
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

export type Erc8004Network = {
  resolve4: (hostname: string) => Promise<string[]>;
  resolve6: (hostname: string) => Promise<string[]>;
  request: (options: https.RequestOptions, callback: (response: IncomingMessage) => void) => ClientRequest;
  rpcPost?: (rpcUrl: string, method: string, params: unknown[], timeoutMs: number) => Promise<unknown>;
};

export class Erc8004ExecutionRevertedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Erc8004ExecutionRevertedError";
  }
}

const DEFAULT_NETWORK: Erc8004Network = {
  resolve4: hostname => dns.resolve4(hostname),
  resolve6: hostname => dns.resolve6(hostname),
  request: https.request as unknown as Erc8004Network["request"],
};

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

export function isErc8004TestnetEnabled(): boolean {
  return process.env.OMNI_ERC8004_ENABLE_TESTNETS === "true";
}

export function getChainConfig(chainRef: string, includeTestnets = isErc8004TestnetEnabled()): Erc8004ChainConfig | undefined {
  return ERC8004_CHAINS[chainRef] ?? (includeTestnets ? ERC8004_TESTNET_CHAINS[chainRef] : undefined);
}

export function getChainRpcUrl(config: Erc8004ChainConfig): string {
  const override = process.env[`ERC8004_RPC_OVERRIDE_${config.chainId}`];
  if (!override) throw new Error(`No operator RPC configured for chain ${config.chainId}; set ERC8004_RPC_OVERRIDE_${config.chainId}`);
  let parsed: URL;
  try {
    parsed = new URL(override);
  } catch {
    throw new Error(`Invalid operator RPC URL for chain ${config.chainId}; HTTPS is required`);
  }
  if (parsed.protocol !== "https:") throw new Error(`Invalid operator RPC URL for chain ${config.chainId}; HTTPS is required`);
  return override;
}

export const ERC8004_PRODUCTION_CHAINS: readonly Erc8004ChainConfig[] = Object.values(ERC8004_CHAINS).filter(c => c.enabled);

// ---------------------------------------------------------------------------
// Public-destination classification
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
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
  ].map(range);
})();

function parseIpv4(ip: string): number[] | undefined {
  const parts = ip.split(".");
  if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return undefined;
  return parts.map(Number);
}

function parseIpv6(ip: string): number[] | undefined {
  if (net.isIP(ip) !== 6) return undefined;
  const [leftRaw, rightRaw, ...extra] = ip.toLowerCase().split("::");
  if (extra.length > 0) return undefined;
  const expand = (part: string): number[] | undefined => {
    if (!part) return [];
    const pieces = part.split(":");
    const result: number[] = [];
    for (let index = 0; index < pieces.length; index++) {
      const piece = pieces[index]!;
      if (piece.includes(".")) {
        if (index !== pieces.length - 1) return undefined;
        const octets = parseIpv4(piece);
        if (!octets) return undefined;
        result.push((octets[0]! << 8) | octets[1]!, (octets[2]! << 8) | octets[3]!);
      } else if (/^[0-9a-f]{1,4}$/.test(piece)) {
        result.push(parseInt(piece, 16));
      } else return undefined;
    }
    return result;
  };
  const left = expand(leftRaw ?? "");
  const right = expand(rightRaw ?? "");
  if (!left || !right) return undefined;
  const units = left.length + right.length;
  if (ip.includes("::")) {
    if (units >= 8) return undefined;
    return [...left, ...Array.from({ length: 8 - units }, () => 0), ...right];
  }
  return units === 8 ? [...left, ...right] : undefined;
}

function ipv6ToBigInt(units: number[]): bigint {
  return units.reduce((value, unit) => (value << 16n) | BigInt(unit), 0n);
}

function ipv6Range(cidr: string): { start: bigint; end: bigint } {
  const [base, bitsText] = cidr.split("/") as [string, string];
  const bits = Number(bitsText);
  const value = ipv6ToBigInt(parseIpv6(base)!);
  const mask = ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - bits)) - 1n);
  const start = value & mask;
  return { start, end: start | (((1n << 128n) - 1n) ^ mask) };
}

const IPV6_ALLOCATED_PUBLIC_RANGES = [
  "2001::/23", "2001:200::/23", "2001:400::/23", "2001:600::/23", "2001:800::/22",
  "2001:c00::/23", "2001:e00::/23", "2001:1200::/23", "2001:1400::/22", "2001:1800::/23",
  "2001:1a00::/23", "2001:1c00::/22", "2001:2000::/19", "2001:4000::/23", "2001:4200::/23",
  "2001:4400::/23", "2001:4600::/23", "2001:4800::/23", "2001:4a00::/23", "2001:4c00::/23",
  "2001:5000::/20", "2001:8000::/19", "2001:a000::/20", "2001:b000::/20", "2003::/18",
  "2400::/12", "2410::/12", "2600::/12", "2610::/23", "2620::/23", "2630::/12",
  "2800::/12", "2a00::/12", "2a10::/12", "2c00::/12",
].map(ipv6Range);

const IPV6_MAPPED_RANGE = ipv6Range("::ffff:0:0/96");
const IPV6_NAT64_RFC6052_RANGE = ipv6Range("64:ff9b::/96");
const IPV6_NAT64_RFC8215_RANGE = ipv6Range("64:ff9b:1::/48");

// Allow-public policy based on the current IANA IPv6 Address Space and
// IPv6 Special-Purpose Address registries. Ordinary destinations must be in
// an allocated public-unicast prefix; everything else is rejected by default.
//
// The entries below are the IANA special-purpose ranges whose current
// registry semantics are not ordinary public destinations. The explicit
// globally-reachable exceptions are allowed intentionally before this deny
// list (for example, current IANA anycast/protocol allocations).
const IPV6_GLOBALLY_REACHABLE_SPECIAL_RANGES = [
  "2001:1::1/128", "2001:1::2/128", "2001:1::3/128", "2001:3::/32",
  "2001:4:112::/48", "2001:20::/28", "2001:30::/28", "2620:4f:8000::/48",
].map(ipv6Range);

const IPV6_NON_GLOBAL_SPECIAL_RANGES = [
  "2001::/23", "2001:2::/48", "2001:10::/28", "2001:db8::/32", "2002::/16",
  "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10",
].map(ipv6Range);

function ipv6ValueInRange(value: bigint, range: { start: bigint; end: bigint }): boolean {
  return value >= range.start && value <= range.end;
}

function ipv4FromUint32(value: bigint): string {
  return [24n, 16n, 8n, 0n].map(shift => Number((value >> shift) & 0xffn)).join(".");
}

function mappedIpv4(units: number[]): string {
  return ipv4FromUint32((BigInt(units[6]!) << 16n) | BigInt(units[7]!));
}

function nat64EmbeddedIpv4(units: number[]): string | undefined {
  const value = ipv6ToBigInt(units);
  if (ipv6ValueInRange(value, IPV6_NAT64_RFC6052_RANGE)) return ipv4FromUint32(value & 0xffffffffn);
  if (!ipv6ValueInRange(value, IPV6_NAT64_RFC8215_RANGE)) return undefined;

  // RFC 6052's /48 format has an eight-bit zero "u" field between the two
  // 16-bit halves of the embedded IPv4 address.
  if ((units[4]! >> 8) !== 0) return undefined;
  const first = BigInt(units[3]!);
  const second = BigInt(((units[4]! & 0xff) << 8) | (units[5]! >> 8));
  return ipv4FromUint32((first << 16n) | second);
}

function isPrivateIpv4(ip: string): boolean {
  const octets = parseIpv4(ip);
  if (!octets) return false;
  const n = octets.reduce((acc, part) => (acc << 8n) | BigInt(part), 0n);
  return PRIVATE_RANGES.some(r => n >= r.start && n <= r.end);
}

function isPublicIpv6(ip: string): boolean {
  const units = parseIpv6(ip);
  if (!units) return false;

  const value = ipv6ToBigInt(units);
  if (ipv6ValueInRange(value, IPV6_MAPPED_RANGE)) return !isPrivateIpv4(mappedIpv4(units));

  const translatedIpv4 = nat64EmbeddedIpv4(units);
  if (translatedIpv4 !== undefined) return !isPrivateIpv4(translatedIpv4);

  if (IPV6_GLOBALLY_REACHABLE_SPECIAL_RANGES.some(range => ipv6ValueInRange(value, range))) return true;
  if (!IPV6_ALLOCATED_PUBLIC_RANGES.some(range => ipv6ValueInRange(value, range))) return false;
  if (IPV6_NON_GLOBAL_SPECIAL_RANGES.some(range => ipv6ValueInRange(value, range))) return false;
  return true;
}

function isPrivateIpv6(ip: string): boolean {
  return parseIpv6(ip) !== undefined && !isPublicIpv6(ip);
}

export function isPrivateIp(ip: string): boolean {
  return isPrivateIpv4(ip) || isPrivateIpv6(ip);
}

/**
 * SAFE POLICY: reject if ANY resolved address is not an eligible public
 * Internet destination. The function name is retained for the existing
 * provider interface, but the IPv6 policy is broader than private CIDRs.
 */
export async function hostnameResolvesToPrivate(hostname: string, network: Erc8004Network = DEFAULT_NETWORK): Promise<boolean> {
  try {
    const [ipv4Results, ipv6Results] = await Promise.all([
      network.resolve4(hostname).catch(() => [] as string[]),
      network.resolve6(hostname).catch(() => [] as string[]),
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
export const MAX_REDIRECTS = 5;

type HardenedFetchResult = { status: number; body: string; finalUrl: string };

async function hardenedFetch(url: string, timeoutMs = 5000, network: Erc8004Network = DEFAULT_NETWORK): Promise<HardenedFetchResult> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new Error(`hardenedFetch: only https:// is supported (got ${parsed.protocol})`);
  }
  const hostname = parsed.hostname;
  const addrs4 = await network.resolve4(hostname).catch(() => [] as string[]);
  const addrs6 = await network.resolve6(hostname).catch(() => [] as string[]);
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
      servername: hostname,
      timeout: timeoutMs,
    };
    const req = network.request(options, (res) => {
      const location = res.headers.location;
      if ((res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 303 || res.statusCode === 307 || res.statusCode === 308) && location) {
        res.resume();
        resolve({ status: res.statusCode ?? 0, body: location, finalUrl: location });
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

function isRedirectStatus(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

async function hardenedFetchWithRedirects(url: string, timeoutMs: number, network: Erc8004Network): Promise<HardenedFetchResult> {
  let currentUrl = url;
  for (let redirectCount = 0; ; redirectCount++) {
    const result = await hardenedFetch(currentUrl, timeoutMs, network);
    if (!isRedirectStatus(result.status)) return result;
    if (!result.body) throw new Error("hardenedFetch: redirect response has no Location header");
    if (redirectCount >= MAX_REDIRECTS) throw new Error(`hardenedFetch: redirect limit exceeded (${MAX_REDIRECTS})`);
    const nextUrl = new URL(result.body, currentUrl);
    if (nextUrl.protocol !== "https:") throw new Error(`hardenedFetch: redirect to non-HTTPS protocol rejected: ${nextUrl.protocol}`);
    currentUrl = nextUrl.toString();
  }
}

// ---------------------------------------------------------------------------
// Low-level JSON-RPC helpers
// ---------------------------------------------------------------------------

type JsonRpcResponse = { id: number; jsonrpc: string; result?: unknown; error?: { code: number; message: string } };

async function rpcPost(rpcUrl: string, method: string, params: unknown[], timeoutMs = 8000, network: Erc8004Network = DEFAULT_NETWORK): Promise<unknown> {
  if (network.rpcPost) return network.rpcPost(rpcUrl, method, params, timeoutMs);
  const hostname = new URL(rpcUrl).hostname;
  const addrs4 = await network.resolve4(hostname).catch(() => [] as string[]);
  const addrs6 = await network.resolve6(hostname).catch(() => [] as string[]);
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
      servername: hostname,
      timeout: timeoutMs,
    };
    const req = network.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        try {
          const json = JSON.parse(Buffer.concat(chunks).toString("utf8")) as JsonRpcResponse;
          if (json.error) {
            if (json.error.code === -32000 && /^execution reverted\b/i.test(json.error.message)) reject(new Erc8004ExecutionRevertedError(json.error.message));
            else reject(new Error(`RPC error ${json.error.code}: ${json.error.message}`));
          } else resolve(json.result);
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
  registrations?: Array<Record<string, unknown>>;
  supportedTrust?: unknown;
};

export type AgentCardValidationResult = {
  card?: AgentCard;
  status: "PARSED" | "VALID" | "INACTIVE" | "SELF_REFERENCE_MATCH" | "SELF_REFERENCE_MISMATCH" | "INVALID" | "UNAVAILABLE";
  parseError?: string;
  structuralError?: string;
  selfReferenceMatch?: boolean;
};

export type AgentCardExpectation = { agentRegistry: string; agentId: bigint | string };

function validateAgentCardStructure(card: AgentCard): string | undefined {
  if (card.type !== "https://eips.ethereum.org/EIPS/eip-8004#registration-v1") return "type must be the ERC-8004 registration-v1 type";
  if (!Array.isArray(card.services) || card.services.length > 64) return "services must be a bounded array";
  for (const svc of card.services) {
    if (typeof svc !== "object" || svc === null || Array.isArray(svc)) return "service must be an object";
    const s = svc as Record<string, unknown>;
    const serviceName = s.name ?? s.type;
    if (typeof serviceName !== "string" || serviceName.length === 0 || serviceName.length > 128) return "service name/type must be a bounded string";
    if (typeof s.endpoint !== "string" || s.endpoint.length === 0 || s.endpoint.length > 2048) return "service endpoint must be a bounded string";
    if (s.type !== undefined && typeof s.type !== "string") return "service type must be a string";
    if (s.name !== undefined && typeof s.name !== "string") return "service name must be a string";
  }
  if (typeof card.x402Support !== "boolean") return "x402Support must be a boolean";
  if (typeof card.active !== "boolean") return "active must be a boolean";
  if (!Array.isArray(card.registrations) || card.registrations.length > 32) return "registrations must be a bounded array";
  for (const registration of card.registrations) {
    if (typeof registration !== "object" || registration === null || Array.isArray(registration)) return "registration must be an object";
    const entry = registration as Record<string, unknown>;
    if (typeof entry.agentRegistry !== "string" || !/^eip155:\d+:0x[a-fA-F0-9]{40}$/.test(entry.agentRegistry)) return "registration agentRegistry is invalid";
    const agentId = entry.agentId;
    if (!((typeof agentId === "string" && /^(0|[1-9]\d*)$/.test(agentId)) || (typeof agentId === "number" && Number.isSafeInteger(agentId) && agentId >= 0))) return "registration agentId is invalid";
  }
  if (card.supportedTrust !== undefined && (!Array.isArray(card.supportedTrust) || card.supportedTrust.length > 32 || card.supportedTrust.some(item => typeof item !== "string" || item.length > 128))) return "supportedTrust must be a bounded string array";
  return undefined;
}

export function parseAgentCard(uri: string, json: unknown, expected?: AgentCardExpectation): AgentCardValidationResult {
  void uri;
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    return { status: "INVALID", parseError: "agent card is not an object" };
  }
  const card = json as AgentCard;
  const structuralError = validateAgentCardStructure(card);
  if (structuralError) return { status: "INVALID", card, parseError: structuralError, structuralError };
  const inactive = card.active === false;
  if (!expected) return { status: inactive ? "INACTIVE" : "VALID", card };
  const expectedId = String(expected.agentId);
  const matches = card.registrations?.some(registration => {
    const entry = registration as Record<string, unknown>;
    return typeof entry.agentRegistry === "string" && entry.agentRegistry.toLowerCase() === expected.agentRegistry.toLowerCase() && String(entry.agentId) === expectedId;
  }) ?? false;
  return { status: matches ? (inactive ? "INACTIVE" : "SELF_REFERENCE_MATCH") : "SELF_REFERENCE_MISMATCH", card, selfReferenceMatch: matches };
}

export function extractServices(card: AgentCard): AgentServiceObservation[] {
  if (!Array.isArray(card.services)) return [];
  return card.services.flatMap(service => {
    if (typeof service !== "object" || service === null) return [];
    const obs: AgentServiceObservation = { type: typeof service.type === "string" ? service.type : typeof service.name === "string" ? service.name : "unknown" };
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
  agentId: bigint,
  network: Erc8004Network = DEFAULT_NETWORK
): Promise<AgentChainIdentityResult> {
  const { chainId, identityRegistry } = config;
  const rpcUrl = getChainRpcUrl(config);

  let ownerAddress: string | undefined;
  try {
    const callData = "0x" + SEL.ownerOf + encodeUint256(agentId);
    const result = await rpcPost(rpcUrl, "eth_call", [{ to: identityRegistry, data: callData }, "latest"], 8000, network) as string;
    if (typeof result !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(result)) throw new Error("malformed ownerOf response");
    ownerAddress = decodeAddress(result.slice(2));
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (e instanceof Erc8004ExecutionRevertedError) {
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
    const result = await rpcPost(rpcUrl, "eth_call", [{ to: identityRegistry, data: callData }, "latest"], 8000, network) as string;
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
    const result = await rpcPost(rpcUrl, "eth_call", [{ to: identityRegistry, data: callData }, "latest"], 8000, network) as string;
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

async function getLatestBlock(rpcUrl: string, network: Erc8004Network): Promise<bigint> {
  const result = await rpcPost(rpcUrl, "eth_blockNumber", [], 8000, network) as string;
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
  maxChunks = REPUTATION_DEFAULT_MAX_CHUNKS,
  network: Erc8004Network = DEFAULT_NETWORK
): Promise<ReputationScanResult> {
  const { reputationRegistry } = config;
  const rpcUrl = getChainRpcUrl(config);
  const errors: string[] = [];

  let latestBlock: bigint;
  try {
    latestBlock = await getLatestBlock(rpcUrl, network);
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
      }], 8000, network) ?? []) as EthLog[];
    } catch (e) {
      errors.push(`eth_getLogs(NewFeedback) ${chunkLabel}: ${e instanceof Error ? e.message : String(e)}`);
    }

    try {
      revokedLogs = (await rpcPost(rpcUrl, "eth_getLogs", [{
        address: reputationRegistry,
        topics: [feedbackRevokedTopic, agentIdPaddedTopic],
        fromBlock: "0x" + fromBlock.toString(16),
        toBlock: "0x" + currentBlock.toString(16),
      }], 8000, network) ?? []) as EthLog[];
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
      // The provider returns the complete bounded observation. Trust filtering is
      // a scoring concern so public feedback remains evidence/statistics.
      const clientAddress = decoded.clientAddress.toLowerCase();
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

    if (fromBlock === 0n) {
      currentBlock = 0n;
      break;
    }
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
  status: AgentCardValidationResult["status"];
  card?: AgentCard;
  rawUri?: string;
  error?: string;
  selfReferenceMatch?: boolean;
};

export async function fetchAgentCard(registrationUri: string, expected?: AgentCardExpectation, network: Erc8004Network = DEFAULT_NETWORK): Promise<AgentCardResult> {
  if (!registrationUri) return { status: "UNAVAILABLE", error: "no registration URI" };

  try {
    if (registrationUri.startsWith("data:application/json;base64,")) {
      const b64 = registrationUri.slice("data:application/json;base64,".length);
      const maxEncodedBytes = 4 * Math.ceil(MAX_REGISTRATION_BODY_BYTES / 3);
      if (b64.length > maxEncodedBytes) {
        return { status: "UNAVAILABLE", rawUri: registrationUri, error: `data URI encoded payload exceeds ${maxEncodedBytes} bytes` };
      }
      const decoded = Buffer.from(b64, "base64");
      if (decoded.length > MAX_REGISTRATION_BODY_BYTES) {
        return { status: "UNAVAILABLE", rawUri: registrationUri, error: `decoded data URI exceeds ${MAX_REGISTRATION_BODY_BYTES} bytes` };
      }
      const json = JSON.parse(decoded.toString("utf8")) as unknown;
      const parsed = parseAgentCard(registrationUri, json, expected);
      if (parsed.parseError) return { status: parsed.status, rawUri: registrationUri, error: parsed.parseError };
      return { status: parsed.status, rawUri: registrationUri, ...(parsed.card ? { card: parsed.card } : {}), ...(parsed.selfReferenceMatch === undefined ? {} : { selfReferenceMatch: parsed.selfReferenceMatch }) };
    }

    const parsed = new URL(registrationUri);

    if (parsed.protocol === "ipfs:") {
      const cid = parsed.hostname || parsed.pathname.replace(/^\//, "");
      if (!cid) return { status: "INVALID", rawUri: registrationUri, error: "IPFS URI has no CID" };
      const gatewayUrl = `https://ipfs.io/ipfs/${cid}${parsed.pathname !== "/" ? parsed.pathname : ""}${parsed.search}`;
      return fetchAgentCardFromHttps(gatewayUrl, registrationUri, expected, network);
    }

    if (parsed.protocol === "https:") {
      return fetchAgentCardFromHttps(registrationUri, registrationUri, expected, network);
    }

    return { status: "INVALID", rawUri: registrationUri, error: `unsupported URI scheme: ${parsed.protocol}` };
  } catch (e) {
    return { status: "UNAVAILABLE", rawUri: registrationUri, error: `invalid registration URI: ${e instanceof Error ? e.message : String(e)}` };
  }
}

async function fetchAgentCardFromHttps(url: string, rawUri: string, expected?: AgentCardExpectation, network: Erc8004Network = DEFAULT_NETWORK): Promise<AgentCardResult> {
  try {
    const result = await hardenedFetchWithRedirects(url, 6000, network);
    if (result.status !== 200) return { status: "UNAVAILABLE", rawUri, error: `agent card HTTP ${result.status}` };
    const json = JSON.parse(result.body) as unknown;
    const parsed = parseAgentCard(rawUri, json, expected);
    if (parsed.parseError) return { status: parsed.status, rawUri, error: parsed.parseError };
    return { status: parsed.status, rawUri, ...(parsed.card ? { card: parsed.card } : {}), ...(parsed.selfReferenceMatch === undefined ? {} : { selfReferenceMatch: parsed.selfReferenceMatch }) };
  } catch (e) {
    return { status: "UNAVAILABLE", rawUri, error: e instanceof Error ? e.message : String(e) };
  }
}

// ---------------------------------------------------------------------------
// Redirect-to-private probe
// ---------------------------------------------------------------------------

export async function probeTargetUrlRedirectsToPrivate(targetUrl: string, network: Erc8004Network = DEFAULT_NETWORK): Promise<{ redirectsToPrivate: boolean; error?: string }> {
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== "https:") return { redirectsToPrivate: false };

    const result = await hardenedFetchWithRedirects(targetUrl, 5000, network).catch(e => {
      if (e instanceof Error && e.message.includes("SSRF rejected")) {
        return { status: 0, body: "", finalUrl: targetUrl, ssrfRejected: true } as HardenedFetchResult & { ssrfRejected?: boolean };
      }
      throw e;
    });

    if ((result as { ssrfRejected?: boolean }).ssrfRejected) return { redirectsToPrivate: true };

    return { redirectsToPrivate: false };
  } catch (e) {
    return { redirectsToPrivate: false, error: e instanceof Error ? e.message : String(e) };
  }
}
