import type { Evidence, MaliciousPackageIndicators, MaliciousPackageObservation, OsvAdvisoryEvidence, OsvAffectedPackage, OsvAffectedRange, OsvCwe, OsvRangeEvent, RiskLevel, VulnerabilityFinding } from "../domain/risk.ts";
import { MALICIOUS_PACKAGE_OBSERVATION_SCHEMA_VERSION } from "../domain/risk.ts";
import { UpstreamHttp } from "./http.ts";

type OsvRawRangeEvent = { introduced?: string; fixed?: string; last_affected?: string; limit?: string };
type OsvRange = { type: string; repo?: string; events: OsvRawRangeEvent[] };
type OsvOrigin = { source?: string; id?: string; modified_time?: string; import_time?: string; sha256?: string; versions?: string[]; ranges?: OsvRange[] };
type OsvCweRecord = { cweId?: string; name?: string; description?: string };
type OsvEvidenceFile = { path?: string; sha256?: string; tlsh?: string };
type OsvPackageIntegrity = { filename?: string; hashes?: Record<string, string> };
type OsvIndicators = { evidence_files?: OsvEvidenceFile[]; package_integrity?: OsvPackageIntegrity[] };
type OsvAffected = {
  package?: { ecosystem?: string; name?: string; purl?: string };
  versions?: string[];
  ranges?: OsvRange[];
  database_specific?: { source?: string; cwes?: OsvCweRecord[]; indicators?: OsvIndicators };
};
type OsvVuln = {
  id: string;
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  withdrawn?: string | null;
  aliases?: string[];
  affected?: OsvAffected[];
  severity?: Array<{ type?: string; score?: string; source?: string }>;
  references?: Array<{ type?: string; url?: string }>;
  database_specific?: { severity?: string; source?: string; "malicious-packages-origins"?: OsvOrigin[] };
  ecosystem_specific?: { severity?: string };
};
type OsvResponse = { vulns?: OsvVuln[] };

function normalizeSeverity(value?: string): RiskLevel {
  const v = value?.toLowerCase();
  if (v === "moderate") return "medium";
  if (v === "critical" || v === "high" || v === "medium" || v === "low") return v;
  return "unknown";
}

function normalizeCvss(values: OsvVuln["severity"]): OsvAdvisoryEvidence["cvss"] {
  return (values ?? [])
    .filter(item => typeof item.type === "string" && item.type.length > 0 && typeof item.score === "string" && item.score.length > 0)
    .map(item => ({ type: item.type!, score: item.score!, ...(item.source ? { source: item.source } : {}) }))
    .sort((left, right) => compareText(JSON.stringify(left), JSON.stringify(right)));
}

function normalizeReferences(values: OsvVuln["references"]): OsvAdvisoryEvidence["references"] {
  const normalized = (values ?? [])
    .filter(item => typeof item.type === "string" && item.type.length > 0 && typeof item.url === "string" && item.url.length > 0)
    .map(item => ({ type: item.type!, url: item.url! }));
  return [...new Map(normalized.map(item => [JSON.stringify(item), item])).values()].sort((left, right) => compareText(JSON.stringify(left), JSON.stringify(right)));
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize).sort((left, right) => compareText(JSON.stringify(left), JSON.stringify(right)));
  if (isRecord(value)) return Object.fromEntries(Object.keys(value).sort(compareText).map(key => [key, canonicalize(value[key])]));
  return value;
}

type Semver = { major: number; minor: number; patch: number; prerelease: string[] };

function parseSemver(value: string): Semver | undefined {
  const match = value.match(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!match) return undefined;
  const numbers = [Number(match[1]), Number(match[2]), Number(match[3])];
  if (numbers.some(number => !Number.isSafeInteger(number))) return undefined;
  return { major: numbers[0]!, minor: numbers[1]!, patch: numbers[2]!, prerelease: match[4]?.split(".") ?? [] };
}

function parseRangeSemver(value: string): Semver | undefined {
  return value === "0" ? { major: 0, minor: 0, patch: 0, prerelease: [] } : parseSemver(value);
}

function compareSemver(left: Semver, right: Semver): number {
  for (const field of ["major", "minor", "patch"] as const) if (left[field] !== right[field]) return left[field] < right[field] ? -1 : 1;
  if (left.prerelease.length === 0 && right.prerelease.length === 0) return 0;
  if (left.prerelease.length === 0) return 1;
  if (right.prerelease.length === 0) return -1;
  for (let index = 0; index < Math.max(left.prerelease.length, right.prerelease.length); index += 1) {
    const leftPart = left.prerelease[index]; const rightPart = right.prerelease[index];
    if (leftPart === undefined) return -1;
    if (rightPart === undefined) return 1;
    if (leftPart === rightPart) continue;
    const leftNumber = /^\d+$/.test(leftPart) ? Number(leftPart) : undefined;
    const rightNumber = /^\d+$/.test(rightPart) ? Number(rightPart) : undefined;
    if (leftNumber !== undefined && rightNumber !== undefined) return leftNumber < rightNumber ? -1 : 1;
    if (leftNumber !== undefined) return -1;
    if (rightNumber !== undefined) return 1;
    return leftPart < rightPart ? -1 : 1;
  }
  return 0;
}

function versionInRange(version: string, range: OsvAffectedRange): boolean {
  if (range.type.toUpperCase() !== "SEMVER") return false;
  const requested = parseSemver(version);
  if (!requested) return false;
  let active = false;
  for (const event of range.events) {
    if (event.introduced !== undefined) {
      const introduced = parseRangeSemver(event.introduced);
      active = introduced !== undefined && compareSemver(requested, introduced) >= 0;
    }
    for (const [field, inclusive] of [["fixed", false], ["lastAffected", true], ["limit", false]] as const) {
      const value = event[field];
      if (value === undefined) continue;
      const endpoint = parseRangeSemver(value);
      if (!endpoint) return false;
      const comparison = compareSemver(requested, endpoint);
      if (active && (inclusive ? comparison <= 0 : comparison < 0)) return true;
      active = false;
    }
  }
  return active;
}

function affectedVersionMatch(affected: OsvAffectedPackage[], ecosystem: string, name: string, version: string): boolean {
  return affected.some(item => {
    if (item.package.ecosystem.toLowerCase() !== ecosystem.toLowerCase() || item.package.name !== name) return false;
    if (item.versions.includes(version)) return true;
    return item.ranges.some(range => versionInRange(version, range));
  });
}

function normalizePackage(value: OsvAffected["package"], fallback: { ecosystem: string; name: string }): OsvAffectedPackage["package"] {
  return {
    ecosystem: stringOrUndefined(value?.ecosystem) ?? fallback.ecosystem,
    name: stringOrUndefined(value?.name) ?? fallback.name,
    ...(stringOrUndefined(value?.purl) ? { purl: value!.purl } : {})
  };
}

function normalizeEvent(event: OsvRawRangeEvent): OsvRangeEvent {
  return {
    ...(stringOrUndefined(event.introduced) ? { introduced: event.introduced } : {}),
    ...(stringOrUndefined(event.fixed) ? { fixed: event.fixed } : {}),
    ...(stringOrUndefined(event.last_affected) ? { lastAffected: event.last_affected } : {}),
    ...(stringOrUndefined(event.limit) ? { limit: event.limit } : {})
  };
}

function normalizeRange(range: OsvRange): OsvAffectedRange {
  return {
    type: range.type,
    ...(range.repo ? { repo: range.repo } : {}),
    events: (range.events ?? []).map(normalizeEvent)
  };
}

function normalizeVersions(versions: string[] | undefined): string[] {
  return [...(versions ?? [])].sort(compareText);
}

function normalizeCwes(cwes: OsvCweRecord[] | undefined): OsvCwe[] | undefined {
  if (!Array.isArray(cwes)) return undefined;
  const normalized = cwes.map(cwe => ({
    ...(stringOrUndefined(cwe.cweId) ? { cweId: cwe.cweId } : {}),
    ...(stringOrUndefined(cwe.name) ? { name: cwe.name } : {}),
    ...(stringOrUndefined(cwe.description) ? { description: cwe.description } : {})
  }));
  return normalized.sort((left, right) => compareText(JSON.stringify(left), JSON.stringify(right)));
}

function normalizeIndicators(indicators: OsvIndicators | undefined): MaliciousPackageIndicators | undefined {
  if (indicators === undefined) return undefined;
  const evidenceFiles = (indicators.evidence_files ?? []).map(file => ({
    ...(stringOrUndefined(file.path) ? { path: file.path } : {}),
    ...(stringOrUndefined(file.sha256) ? { sha256: file.sha256 } : {}),
    ...(stringOrUndefined(file.tlsh) ? { tlsh: file.tlsh } : {})
  })).sort((left, right) => compareText(JSON.stringify(left), JSON.stringify(right)));
  const packageIntegrity = (indicators.package_integrity ?? []).map(item => ({
    ...(stringOrUndefined(item.filename) ? { filename: item.filename } : {}),
    hashes: Object.fromEntries(Object.entries(item.hashes ?? {}).filter(([, value]) => typeof value === "string").sort(([left], [right]) => compareText(left, right)))
  })).sort((left, right) => compareText(JSON.stringify(left), JSON.stringify(right)));
  return { evidenceFiles, packageIntegrity };
}

function normalizeAffected(affected: OsvAffected[] | undefined, fallback: { ecosystem: string; name: string }): OsvAffectedPackage[] {
  return (affected ?? [])
    .map(item => {
      const packageInfo = normalizePackage(item.package, fallback);
      const sourceReference = stringOrUndefined(item.database_specific?.source);
      const cwes = normalizeCwes(item.database_specific?.cwes);
      const indicators = normalizeIndicators(item.database_specific?.indicators);
      return {
        package: packageInfo,
        versions: normalizeVersions(item.versions),
        ranges: (item.ranges ?? []).map(normalizeRange).sort((left, right) => compareText(JSON.stringify(left), JSON.stringify(right))),
        ...(sourceReference ? { sourceReference } : {}),
        ...(cwes ? { cwes } : {}),
        ...(indicators ? { indicators } : {})
      };
    })
    .sort((left, right) => compareText(JSON.stringify(left), JSON.stringify(right)));
}

function normalizeOrigins(origins: OsvOrigin[] | undefined): MaliciousPackageObservation["origins"] {
  return (origins ?? [])
    .filter(origin => typeof origin.source === "string" && origin.source.length > 0)
    .map(origin => ({
      source: origin.source!,
      ...(stringOrUndefined(origin.id) ? { id: origin.id } : {}),
      ...(stringOrUndefined(origin.modified_time) ? { modifiedAt: origin.modified_time } : {}),
      ...(stringOrUndefined(origin.import_time) ? { importedAt: origin.import_time } : {}),
      ...(stringOrUndefined(origin.sha256) ? { sha256: origin.sha256 } : {}),
      ...(Array.isArray(origin.versions) ? { versions: normalizeVersions(origin.versions) } : {}),
      ...(Array.isArray(origin.ranges) ? { ranges: origin.ranges.map(normalizeRange).sort((left, right) => compareText(JSON.stringify(left), JSON.stringify(right))) } : {})
    }))
    .sort((left, right) => compareText(JSON.stringify(left), JSON.stringify(right)));
}

function advisoryEvidence(vulnerability: OsvVuln, ecosystem: string, name: string, version: string): OsvAdvisoryEvidence {
  const affected = normalizeAffected(vulnerability.affected, { ecosystem, name });
  const matchingPackage = affected.some(item => item.package.ecosystem.toLowerCase() === ecosystem.toLowerCase() && item.package.name === name);
  const matchedVersion = affectedVersionMatch(affected, ecosystem, name, version);
  const databaseSeverity = stringOrUndefined(vulnerability.database_specific?.severity);
  const ecosystemSeverity = stringOrUndefined(vulnerability.ecosystem_specific?.severity);
  return {
    id: vulnerability.id,
    aliases: [...new Set((vulnerability.aliases ?? []).filter(alias => typeof alias === "string" && alias.length > 0))].sort(compareText),
    raw: canonicalize(vulnerability) as Record<string, unknown>,
    ...(vulnerability.summary ? { summary: vulnerability.summary } : {}),
    ...(vulnerability.details ? { details: vulnerability.details } : {}),
    ...(vulnerability.database_specific?.source ? { sourceReference: vulnerability.database_specific.source } : {}),
    severity: normalizeSeverity(databaseSeverity ?? ecosystemSeverity),
    ...(databaseSeverity ? { severitySource: "database_specific.severity" } : ecosystemSeverity ? { severitySource: "ecosystem_specific.severity" } : {}),
    cvss: normalizeCvss(vulnerability.severity),
    ...(vulnerability.published ? { published: vulnerability.published } : {}),
    ...(vulnerability.modified ? { modified: vulnerability.modified } : {}),
    ...(vulnerability.withdrawn !== undefined ? { withdrawn: vulnerability.withdrawn } : {}),
    affected,
    references: normalizeReferences(vulnerability.references),
    versionMatch: {
      ecosystem,
      name,
      version,
      matched: matchedVersion,
      queryMatched: true,
      rationale: matchedVersion ? "OSV exact-version query and affected range matched the requested package version" : matchingPackage ? "OSV exact-version query returned the package but its affected ranges did not match the requested version" : "OSV exact-version query returned an advisory without a matching affected package entry"
    }
  };
}

function unionFind(size: number): { find(index: number): number; join(left: number, right: number): void } {
  const parents = Array.from({ length: size }, (_, index) => index);
  const find = (index: number): number => {
    let root = index;
    while (parents[root] !== root) root = parents[root]!;
    while (parents[index] !== index) { const next = parents[index]!; parents[index] = root; index = next; }
    return root;
  };
  const join = (left: number, right: number): void => {
    const leftRoot = find(left); const rightRoot = find(right);
    if (leftRoot !== rightRoot) parents[rightRoot] = leftRoot;
  };
  return { find, join };
}

function groupedFindings(vulnerabilities: OsvVuln[], ecosystem: string, name: string, version: string): { findings: VulnerabilityFinding[]; advisories: OsvAdvisoryEvidence[] } {
  const records = vulnerabilities.map(record => ({ record, advisory: advisoryEvidence(record, ecosystem, name, version) }));
  const compareRecords = (left: typeof records[number], right: typeof records[number]): number => compareText(left.advisory.id, right.advisory.id) || compareText(JSON.stringify(left.advisory), JSON.stringify(right.advisory));
  const advisories = records.map(item => item.advisory).sort((left, right) => compareText(left.id, right.id) || compareText(JSON.stringify(left), JSON.stringify(right)));
  const activeRecords = records.filter(item => item.record.withdrawn == null);
  if (activeRecords.some(item => !item.advisory.versionMatch.matched)) throw new Error("osv_advisory_version_mismatch");
  const ordered = activeRecords.sort(compareRecords);
  const identities = ordered.map(item => new Set([item.record.id, ...(item.record.aliases ?? [])]));
  const groups = unionFind(ordered.length);
  for (let left = 0; left < ordered.length; left += 1) {
    for (let right = left + 1; right < ordered.length; right += 1) {
      if ([...identities[left]!].some(identity => identities[right]!.has(identity))) groups.join(left, right);
    }
  }
  const grouped = new Map<number, typeof records>();
  for (let index = 0; index < ordered.length; index += 1) {
    const root = groups.find(index);
    grouped.set(root, [...(grouped.get(root) ?? []), ordered[index]!]);
  }
  const ranks: Record<RiskLevel, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const findings: VulnerabilityFinding[] = [];
  for (const group of grouped.values()) {
    const normalized = group.map(item => item.advisory);
    const advisoryIds = [...new Set(group.map(item => item.record.id))].sort(compareText);
    const allIdentities = new Set(group.flatMap(item => [item.record.id, ...(item.record.aliases ?? [])]));
    const id = advisoryIds[0]!;
    allIdentities.delete(id);
    const severity = normalized.reduce<RiskLevel>((maximum, item) => ranks[item.severity] > ranks[maximum] ? item.severity : maximum, "unknown");
    findings.push({ id, severity, knownExploited: false, aliases: [...allIdentities].sort(compareText), ...(advisoryIds.length > 1 ? { advisoryIds } : {}) });
  }
  return { findings: findings.sort((left, right) => compareText(left.id, right.id)), advisories };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function optionalString(value: unknown): boolean {
  return value === undefined || (typeof value === "string" && value.length > 0);
}

function stringArray(value: unknown): boolean {
  return Array.isArray(value) && value.every(item => typeof item === "string" && item.length > 0);
}

function validRange(value: unknown): boolean {
  if (!isRecord(value) || typeof value.type !== "string" || value.type.length === 0 || !Array.isArray(value.events)) return false;
  const type = value.type;
  if (value.repo !== undefined && typeof value.repo !== "string") return false;
  return value.events.every(event => {
    if (!isRecord(event) || !optionalString(event.introduced) || !optionalString(event.fixed) || !optionalString(event.last_affected) || !optionalString(event.limit)) return false;
    if (type.toUpperCase() !== "SEMVER") return true;
    return [event.introduced, event.fixed, event.last_affected, event.limit].every(item => item === undefined || (typeof item === "string" && parseRangeSemver(item) !== undefined));
  });
}

function validAffectedDatabaseSpecific(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (!optionalString(value.source)) return false;
  if (value.cwes !== undefined && (!Array.isArray(value.cwes) || value.cwes.some(item => !isRecord(item) || !optionalString(item.cweId) || !optionalString(item.name) || !optionalString(item.description)))) return false;
  if (value.indicators !== undefined) {
    if (!isRecord(value.indicators)) return false;
    if (value.indicators.evidence_files !== undefined && (!Array.isArray(value.indicators.evidence_files) || value.indicators.evidence_files.some(item => !isRecord(item) || !optionalString(item.path) || !optionalString(item.sha256) || !optionalString(item.tlsh)))) return false;
    if (value.indicators.package_integrity !== undefined && (!Array.isArray(value.indicators.package_integrity) || value.indicators.package_integrity.some(item => !isRecord(item) || !optionalString(item.filename) || !isRecord(item.hashes) || Object.values(item.hashes).some(hash => typeof hash !== "string")))) return false;
  }
  return true;
}

function validAffected(value: unknown): boolean {
  if (!Array.isArray(value) || value.length === 0) return false;
  return value.every(item => {
    if (!isRecord(item) || !isRecord(item.package) || typeof item.package.ecosystem !== "string" || item.package.ecosystem.length === 0 || typeof item.package.name !== "string" || item.package.name.length === 0) return false;
    if (item.package.purl !== undefined && !optionalString(item.package.purl)) return false;
    if (item.versions !== undefined && !stringArray(item.versions)) return false;
    if (item.ranges !== undefined && (!Array.isArray(item.ranges) || !item.ranges.every(validRange))) return false;
    if (item.database_specific !== undefined && !validAffectedDatabaseSpecific(item.database_specific)) return false;
    return true;
  });
}

function validVulnerability(value: unknown): value is OsvVuln {
  if (!isRecord(value) || typeof value.id !== "string" || value.id.length === 0) return false;
  if (!optionalString(value.summary) || !optionalString(value.details) || !optionalString(value.published) || !optionalString(value.modified) || !(value.withdrawn === undefined || value.withdrawn === null || typeof value.withdrawn === "string")) return false;
  if (value.aliases !== undefined && !stringArray(value.aliases)) return false;
  if (value.affected !== undefined && !validAffected(value.affected)) return false;
  if (value.severity !== undefined && (!Array.isArray(value.severity) || value.severity.some(item => !isRecord(item) || !optionalString(item.type) || !optionalString(item.score) || (item.source !== undefined && !optionalString(item.source))))) return false;
  if (value.references !== undefined && (!Array.isArray(value.references) || value.references.some(item => !isRecord(item) || !optionalString(item.type) || !optionalString(item.url)))) return false;
  if (value.database_specific !== undefined) {
    if (!isRecord(value.database_specific) || !optionalString(value.database_specific.severity) || !optionalString(value.database_specific.source)) return false;
    const origins = value.database_specific["malicious-packages-origins"];
    if (origins !== undefined && (!Array.isArray(origins) || origins.some(origin => !isRecord(origin) || typeof origin.source !== "string" || !optionalString(origin.id) || !optionalString(origin.modified_time) || !optionalString(origin.import_time) || !optionalString(origin.sha256) || (origin.versions !== undefined && !stringArray(origin.versions)) || (origin.ranges !== undefined && (!Array.isArray(origin.ranges) || !origin.ranges.every(validRange)))))) return false;
  }
  if (value.ecosystem_specific !== undefined && (!isRecord(value.ecosystem_specific) || !optionalString(value.ecosystem_specific.severity))) return false;
  return true;
}

function responseVulnerabilities(data: OsvResponse): OsvVuln[] {
  if (!isRecord(data) || !Array.isArray(data.vulns) || !data.vulns.every(validVulnerability)) throw new Error("osv_response_malformed");
  return data.vulns;
}

function uniqueVulnerabilities(vulnerabilities: OsvVuln[], rejectConflicts: boolean): OsvVuln[] {
  const unique = new Map<string, { record: OsvVuln; normalized: string }>();
  for (const record of vulnerabilities) {
    const normalized = JSON.stringify(canonicalize(record));
    const existing = unique.get(record.id);
    if (existing && existing.normalized !== normalized) {
      if (rejectConflicts) throw new Error("osv_duplicate_advisory_id_conflict");
      if (normalized < existing.normalized) unique.set(record.id, { record, normalized });
    } else if (!existing) unique.set(record.id, { record, normalized });
  }
  return [...unique.values()].sort((left, right) => compareText(left.record.id, right.record.id)).map(item => item.record);
}

function maliciousObservation(vulnerability: OsvVuln, ecosystem: string, name: string, version: string): MaliciousPackageObservation {
  const affected = normalizeAffected(vulnerability.affected, { ecosystem, name });
  const packageInfo = affected[0]?.package ?? { ecosystem, name };
  const sourceReference = affected.find(item => item.sourceReference)?.sourceReference
    ?? stringOrUndefined(vulnerability.database_specific?.source);
  return {
    schemaVersion: MALICIOUS_PACKAGE_OBSERVATION_SCHEMA_VERSION,
    id: vulnerability.id,
    package: packageInfo,
    queriedVersion: version,
    ...(stringOrUndefined(vulnerability.published) ? { published: vulnerability.published } : {}),
    ...(stringOrUndefined(vulnerability.modified) ? { modified: vulnerability.modified } : {}),
    ...(sourceReference ? { sourceReference } : {}),
    affected,
    origins: normalizeOrigins(vulnerability.database_specific?.["malicious-packages-origins"])
  };
}

export class OsvProvider {
  constructor(private readonly http: UpstreamHttp) {}

  async packageVulnerabilities(ecosystem: string, name: string, version: string): Promise<{ findings: VulnerabilityFinding[]; maliciousPackageObservations: MaliciousPackageObservation[]; evidence: Evidence[] }> {
    const body = { package: { ecosystem, name }, version };
    const data = await this.http.json<OsvResponse>("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });

    const rawVulnerabilities = responseVulnerabilities(data);
    const maliciousPackageObservations = uniqueVulnerabilities(rawVulnerabilities.filter(vulnerability => vulnerability.id.startsWith("MAL-")), false)
      .filter(vulnerability => vulnerability.id.startsWith("MAL-") && vulnerability.withdrawn == null)
      .map(vulnerability => maliciousObservation(vulnerability, ecosystem, name, version))
      .sort((left, right) => compareText(JSON.stringify(left), JSON.stringify(right)));
    const vulnerabilities = uniqueVulnerabilities(rawVulnerabilities.filter(vulnerability => !vulnerability.id.startsWith("MAL-")), true);
    const grouped = groupedFindings(vulnerabilities, ecosystem, name, version);
    const findings = grouped.findings;
    return {
      findings,
      maliciousPackageObservations,
      evidence: [{
        source: "OSV",
        kind: "package_vulnerabilities",
        observedAt: new Date().toISOString(),
        detail: {
          ecosystem,
          name,
          version,
          vulnerabilityIds: grouped.advisories.filter(advisory => findings.some(finding => (finding.advisoryIds ?? [finding.id]).includes(advisory.id))).map(advisory => advisory.id),
          advisories: grouped.advisories,
          ...(maliciousPackageObservations.length > 0 ? { maliciousPackageIds: maliciousPackageObservations.map(observation => observation.id) } : {})
        }
      }]
    };
  }
}
