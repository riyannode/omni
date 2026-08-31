import { resolve4, resolve6 } from "node:dns/promises";
import { isIP } from "node:net";

export type ResolvedPublicAddress = { address: string; family: 4 | 6 };
export type ClassifiedNetworkAddress = ResolvedPublicAddress & { classification: "public" | "private" | "loopback" | "link_local" | "multicast" | "unspecified" | "reserved" };
export type AddressResolver = (hostname: string) => Promise<ResolvedPublicAddress[]>;

function ipv4Number(address: string): number {
  return address.split(".").reduce((value, part) => value * 256 + Number(part), 0) >>> 0;
}
function inRange(value: number, start: number, end: number): boolean { return value >= start && value <= end; }
function isDisallowedIpv4(address: string): boolean {
  const value = ipv4Number(address);
  const octets = address.split(".").map(Number);
  const first = octets[0] ?? -1;
  const second = octets[1] ?? -1;
  return first === 0 || first === 10 || first === 127 || (first === 100 && inRange(second, 64, 127))
    || (first === 169 && second === 254) || (first === 172 && inRange(second, 16, 31))
    || (first === 192 && second === 0) || (first === 192 && second === 2) || (first === 192 && second === 88)
 || (first === 192 && second === 31 && octets[2] === 196) || (first === 192 && second === 52 && octets[2] === 193)
 || (first === 192 && second === 175 && octets[2] === 48)
    || (first === 192 && second === 168) || (first === 198 && inRange(second, 18, 19))
    || (first === 198 && second === 51) || (first === 203 && second === 0 && octets[2] === 113)
    || first >= 224 || value === 0xffffffff;
}
function ipv6Number(address: string): bigint {
  let normalized = address.toLowerCase().split("%", 1)[0]!;
  const ipv4Tail = normalized.match(/(?:^|:)(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  if (ipv4Tail) {
    const value = ipv4Number(ipv4Tail);
    normalized = `${normalized.slice(0, normalized.length - ipv4Tail.length)}${(value >>> 16).toString(16)}:${(value & 0xffff).toString(16)}`;
  }
  const halves = normalized.split("::");
  const left = halves[0] ? halves[0].split(":").filter(Boolean) : [];
  const right = halves.length > 1 && halves[1] ? halves[1].split(":").filter(Boolean) : [];
  const groups = halves.length === 1 ? left : [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
  return groups.reduce((value, group) => (value << 16n) | BigInt(parseInt(group || "0", 16)), 0n);
}
function inIpv6Prefix(address: string, prefix: bigint, bits: number): boolean {
  const mask = ((1n << BigInt(bits)) - 1n) << BigInt(128 - bits);
  return (ipv6Number(address) & mask) === (prefix & mask);
}
function isDisallowedIpv6(address: string): boolean {
  const value = ipv6Number(address);
  return value === 0n || value === 1n || inIpv6Prefix(address, 0xfcn << 120n, 7)
    || inIpv6Prefix(address, 0xfe80n << 112n, 10) || inIpv6Prefix(address, 0xffn << 120n, 8)
    || inIpv6Prefix(address, 0x20010db8n << 96n, 32) || inIpv6Prefix(address, 0x20010000n << 96n, 32)
    || inIpv6Prefix(address, 0x20010n << 100n, 28) || inIpv6Prefix(address, 0x2002n << 112n, 16)
    || inIpv6Prefix(address, 0n, 96) || inIpv6Prefix(address, 0xffffn << 32n, 96);
}
export function isDisallowedAddress(address: string): boolean {
  const family = isIP(address);
  return family === 4 ? isDisallowedIpv4(address) : family === 6 ? isDisallowedIpv6(address) : true;
}
export function isDisallowedHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  return !normalized || normalized === "localhost" || normalized.endsWith(".localhost") || normalized.endsWith(".local") || normalized.endsWith(".internal") || (isIP(normalized) !== 0 && isDisallowedAddress(normalized));
}
function classify(address: string): ClassifiedNetworkAddress["classification"] {
  if (!isDisallowedAddress(address)) return "public";
  if (isIP(address) === 4) {
    const octets = address.split(".").map(Number);
    const first = octets[0] ?? -1;
    const second = octets[1] ?? -1;
    if (first === 127) return "loopback";
    if (first === 169 && second === 254) return "link_local";
    if (first >= 224) return "multicast";
    if (first === 0) return "unspecified";
    if (first === 10 || first === 172 || first === 192 || first === 100) return "private";
  } else if (isIP(address) === 6) {
    if (address === "::" || address === "::1") return address === "::" ? "unspecified" : "loopback";
    const lower = address.toLowerCase();
    if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) return "link_local";
    if (lower.startsWith("ff")) return "multicast";
    if (lower.startsWith("fc") || lower.startsWith("fd")) return "private";
  }
  return "reserved";
}

export class PublicNetworkPolicy {
  private readonly resolveHost: AddressResolver;
  constructor(resolveHost: AddressResolver = async hostname => {
    const results = await Promise.allSettled([resolve4(hostname), resolve6(hostname)]);
    const addresses = results.flatMap((result, index) => result.status === "fulfilled" ? result.value.map(address => ({ address, family: (index === 0 ? 4 : 6) as 4 | 6 })) : []);
    if (addresses.length === 0) throw new Error("host did not resolve");
    return addresses;
  }) { this.resolveHost = resolveHost; }

  async resolveAndValidate(hostname: string): Promise<ResolvedPublicAddress[]> {
    const classified = await this.resolveAndClassify(hostname);
    if (classified.length === 0 || classified.some(item => item.classification !== "public")) throw new Error("disallowed network target");
    return classified.map(({ address, family }) => ({ address, family }));
  }

  async resolveAndClassify(hostname: string): Promise<ClassifiedNetworkAddress[]> {
    const normalized = hostname.toLowerCase().replace(/\.$/, "");
    if (isDisallowedHostname(normalized) && isIP(normalized) === 0) throw new Error("disallowed network target");
    const directFamily = isIP(normalized);
    const addresses = directFamily === 0 ? await this.resolveHost(normalized) : [{ address: normalized, family: directFamily as 4 | 6 }];
    return [...addresses].sort((left, right) => left.family - right.family || left.address.localeCompare(right.address)).map(item => ({ ...item, classification: classify(item.address) }));
  }
}
