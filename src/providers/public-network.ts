import { resolve4, resolve6 } from "node:dns/promises";
import { isIP } from "node:net";
import { UpstreamAdmission } from "./http.ts";

export type ResolvedPublicAddress = { address: string; family: 4 | 6 };
export type ClassifiedNetworkAddress = ResolvedPublicAddress & { classification: "public" | "private" | "loopback" | "link_local" | "multicast" | "unspecified" | "reserved" };
export type AddressResolver = (hostname: string) => Promise<ResolvedPublicAddress[]>;
type NetworkClassification = Exclude<ClassifiedNetworkAddress["classification"], "public">;
type Cidr = { family: 4 | 6; network: number | bigint; bits: number; classification: NetworkClassification };

const IANA_IPV4_REGISTRY_URL = "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv";
const IANA_IPV6_REGISTRY_URL = "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv";
const IANA_REGISTRY_REVIEW_DATE = "2026-08-31";

function ipv4Number(address: string): number {
  return address.split(".").reduce((value, part) => value * 256 + Number(part), 0) >>> 0;
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
function cidr(network: string, classification: NetworkClassification): Cidr {
  const [address, bitsText] = network.split("/");
  const family = isIP(address!);
  if ((family !== 4 && family !== 6) || !bitsText) throw new Error(`invalid CIDR table entry: ${network}`);
  const bits = Number(bitsText);
  return { family: family as 4 | 6, network: family === 4 ? ipv4Number(address!) : ipv6Number(address!), bits, classification };
}
function matches(address: string, entry: Cidr): boolean {
  const family = isIP(address);
  if (family !== entry.family) return false;
  const value = family === 4 ? ipv4Number(address) : ipv6Number(address);
  const width = family === 4 ? 32 : 128;
  const mask = ((1n << BigInt(entry.bits)) - 1n) << BigInt(width - entry.bits);
  return (BigInt(value) & mask) === (BigInt(entry.network) & mask);
}

// Only prefixes whose IANA registry row is not globally reachable are denied.
// IANA rows marked globally reachable TRUE (for example 192.31.196.0/24,
// 192.52.193.0/24, and 64:ff9b::/96) remain usable public addresses.
const SPECIAL_PURPOSE_PREFIXES: Cidr[] = [
  cidr("0.0.0.0/8", "unspecified"), cidr("10.0.0.0/8", "private"), cidr("100.64.0.0/10", "private"), cidr("127.0.0.0/8", "loopback"), cidr("169.254.0.0/16", "link_local"), cidr("172.16.0.0/12", "private"),
  cidr("192.0.0.0/24", "reserved"), cidr("192.0.2.0/24", "reserved"), cidr("192.88.99.0/24", "reserved"), cidr("192.168.0.0/16", "private"), cidr("198.18.0.0/15", "reserved"), cidr("198.51.100.0/24", "reserved"), cidr("203.0.113.0/24", "reserved"), cidr("224.0.0.0/4", "multicast"), cidr("240.0.0.0/4", "reserved"), cidr("255.255.255.255/32", "reserved"),
  cidr("::/128", "unspecified"), cidr("::1/128", "loopback"), cidr("::ffff:0:0/96", "reserved"), cidr("64:ff9b:1::/48", "reserved"), cidr("100::/64", "reserved"), cidr("100:0:0:1::/64", "reserved"), cidr("2001::/23", "reserved"), cidr("2001:2::/48", "reserved"), cidr("2001:10::/28", "reserved"), cidr("2001:db8::/32", "reserved"), cidr("2002::/16", "reserved"), cidr("3fff::/20", "reserved"), cidr("5f00::/16", "reserved"), cidr("fc00::/7", "private"), cidr("fec0::/10", "reserved"), cidr("fe80::/10", "link_local"), cidr("ff00::/8", "multicast")
];
const SPECIAL_PURPOSE_EXCEPTIONS: Cidr[] = [cidr("192.0.0.9/32", "reserved"), cidr("192.0.0.10/32", "reserved"), cidr("2001:1::1/128", "reserved"), cidr("2001:1::2/128", "reserved"), cidr("2001:1::3/128", "reserved"), cidr("2001:3::/32", "reserved"), cidr("2001:4:112::/48", "reserved"), cidr("2001:20::/28", "reserved"), cidr("2001:30::/28", "reserved")];

function disallowedClassification(address: string): NetworkClassification | undefined {
  if (SPECIAL_PURPOSE_EXCEPTIONS.some(entry => matches(address, entry))) return undefined;
  return SPECIAL_PURPOSE_PREFIXES.find(entry => matches(address, entry))?.classification;
}
export function isDisallowedAddress(address: string): boolean { return isIP(address) === 0 || disallowedClassification(address) !== undefined; }
export function isDisallowedHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  return !normalized || normalized === "localhost" || normalized.endsWith(".localhost") || normalized.endsWith(".local") || normalized.endsWith(".internal") || (isIP(normalized) !== 0 && isDisallowedAddress(normalized));
}
function classify(address: string): ClassifiedNetworkAddress["classification"] { return disallowedClassification(address) ?? "public"; }

export class PublicNetworkPolicy {
  private readonly resolveHost: AddressResolver;
  constructor(resolveHost?: AddressResolver, admission = new UpstreamAdmission(256, 2048)) {
    this.resolveHost = resolveHost ?? (async hostname => {
      const results = await Promise.allSettled([admission.run(() => resolve4(hostname)), admission.run(() => resolve6(hostname))]);
      const addresses = results.flatMap((result, index) => result.status === "fulfilled" ? result.value.map(address => ({ address, family: (index === 0 ? 4 : 6) as 4 | 6 })) : []);
      if (addresses.length === 0) throw new Error("host did not resolve");
      return addresses;
    });
  }

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

export const PUBLIC_NETWORK_POLICY_SOURCE = { ipv4: IANA_IPV4_REGISTRY_URL, ipv6: IANA_IPV6_REGISTRY_URL, reviewedAt: IANA_REGISTRY_REVIEW_DATE } as const;
