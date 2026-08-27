import type { Evidence, MaliciousPackageIndicators, MaliciousPackageObservation, OsvAffectedPackage, OsvAffectedRange, OsvCwe, OsvRangeEvent, RiskLevel, VulnerabilityFinding } from "../domain/risk.ts";
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
  published?: string;
  modified?: string;
  aliases?: string[];
  affected?: OsvAffected[];
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

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
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
        versions: [...(item.versions ?? [])],
        ranges: (item.ranges ?? []).map(normalizeRange),
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
      ...(Array.isArray(origin.versions) ? { versions: [...origin.versions] } : {}),
      ...(Array.isArray(origin.ranges) ? { ranges: origin.ranges.map(normalizeRange) } : {})
    }))
    .sort((left, right) => compareText(JSON.stringify(left), JSON.stringify(right)));
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

    const vulnerabilities = data.vulns ?? [];
    const maliciousPackageObservations = vulnerabilities
      .filter(vulnerability => vulnerability.id.startsWith("MAL-"))
      .map(vulnerability => maliciousObservation(vulnerability, ecosystem, name, version))
      .sort((left, right) => compareText(left.id, right.id));
    const findings = vulnerabilities
      .filter(vulnerability => !vulnerability.id.startsWith("MAL-"))
      .map(vulnerability => ({
        id: vulnerability.id,
        severity: normalizeSeverity(vulnerability.database_specific?.severity ?? vulnerability.ecosystem_specific?.severity),
        knownExploited: false,
        aliases: vulnerability.aliases ?? []
      }));
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
          vulnerabilityIds: findings.map(v => v.id),
          ...(maliciousPackageObservations.length > 0 ? { maliciousPackageIds: maliciousPackageObservations.map(observation => observation.id) } : {})
        }
      }]
    };
  }
}
