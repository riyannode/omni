import type { Evidence, ExactDependencyCoordinate, ProvenanceObservation } from "../domain/risk.ts";
import type { UpstreamHttp } from "./http.ts";

type Http = Pick<UpstreamHttp, "json">;
type Expected = { repository?: string; commit?: string };
type Attestation = { verified?: boolean; sourceRepository?: string; commit?: string; url?: string };
type ResponseData = { licenses?: string[]; advisoryKeys?: Array<{ id?: string }>; relatedProjects?: Array<{ projectKey?: { id?: string }; relationType?: string; relationProvenance?: string }>; slsaProvenances?: Attestation[]; attestations?: Attestation[] };

function repository(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try { const url = value.includes("://") ? new URL(value) : new URL(`https://${value}`); return `${url.hostname.toLowerCase()}${url.pathname.replace(/^\//, "").replace(/\.git$/, "").replace(/\/$/, "")}`; } catch { return undefined; }
}

export function normalizeProvenance(attestation: Attestation | undefined, expected: Expected = {}): Omit<ProvenanceObservation, "package" | "source"> {
  if (!attestation) return { state: "UNAVAILABLE" };
  const sourceRepository = repository(attestation.sourceRepository); const sourceCommit = attestation.commit;
  if (attestation.verified !== true) return { state: "PRESENT_UNVERIFIED", ...(sourceRepository ? { sourceRepository } : {}), ...(sourceCommit ? { sourceCommit } : {}), ...(attestation.url ? { attestationUrl: attestation.url } : {}) };
  if (!sourceRepository) return { state: "ERROR", ...(sourceCommit ? { sourceCommit } : {}), ...(attestation.url ? { attestationUrl: attestation.url } : {}) };
  const expectedRepository = repository(expected.repository);
  if (expectedRepository && expectedRepository !== sourceRepository) return { state: "VERIFIED_SOURCE_MISMATCH", sourceRepository, ...(sourceCommit ? { sourceCommit } : {}), expectedSourceMatches: false, ...(attestation.url ? { attestationUrl: attestation.url } : {}) };
  if (expected.commit && sourceCommit && expected.commit.toLowerCase() !== sourceCommit.toLowerCase()) return { state: "VERIFIED_COMMIT_MISMATCH", sourceRepository, sourceCommit, ...(expectedRepository ? { expectedSourceMatches: true } : {}), expectedCommitMatches: false, ...(attestation.url ? { attestationUrl: attestation.url } : {}) };
  return { state: "VERIFIED", sourceRepository, ...(sourceCommit ? { sourceCommit } : {}), ...(expectedRepository ? { expectedSourceMatches: true } : {}), ...(expected.commit && sourceCommit ? { expectedCommitMatches: true } : {}), ...(attestation.url ? { attestationUrl: attestation.url } : {}) };
}

function expectation(data: ResponseData): Expected {
  const candidates = (data.relatedProjects ?? []).filter(item => item.relationType === "SOURCE_REPO" && item.relationProvenance !== "UNVERIFIED_METADATA").map(item => repository(item.projectKey?.id)).filter((item): item is string => item !== undefined);
  const candidate = candidates[0];
  return candidate === undefined ? {} : { repository: candidate };
}

export class DepsDevProvider {
  constructor(private readonly http: Http) {}

  async packageVersion(coordinate: ExactDependencyCoordinate, expected: Expected = {}): Promise<{ licenses: string[]; advisories: string[]; provenance: ProvenanceObservation[]; graph: { checked: boolean; nodeCount: number; error?: string }; evidence: Evidence }> {
    const base = `https://api.deps.dev/v3/systems/${coordinate.ecosystem}/packages/${encodeURIComponent(coordinate.name)}/versions/${encodeURIComponent(coordinate.version)}`;
    const data = await this.http.json<ResponseData>(base);
    let graph: { checked: boolean; nodeCount: number; error?: string };
    try {
      const graphData = await this.http.json<{ nodes?: unknown[] }>(`${base}:dependencies`);
      graph = { checked: true, nodeCount: Array.isArray(graphData.nodes) ? graphData.nodes.length : 0 };
    } catch (error) { graph = { checked: false, nodeCount: 0, error: error instanceof Error ? error.message : "unknown error" }; }
    const normalized = normalizeProvenance(data.slsaProvenances?.[0] ?? data.attestations?.[0], expected.repository || expected.commit ? expected : expectation(data));
    const licenses = [...new Set((data.licenses ?? []).filter((item): item is string => typeof item === "string"))].sort();
    const advisories = [...new Set((data.advisoryKeys ?? []).flatMap(item => typeof item.id === "string" ? [item.id] : []))].sort();
    return { licenses, advisories, graph, provenance: [{ package: coordinate, source: "deps.dev", ...normalized }], evidence: { source: "deps.dev", kind: "package_dependency_provenance", observedAt: new Date().toISOString(), detail: { ecosystem: coordinate.ecosystem, name: coordinate.name, version: coordinate.version, licenses, advisoryIds: advisories, provenanceState: normalized.state, ...(normalized.sourceRepository ? { sourceRepository: normalized.sourceRepository } : {}), ...(normalized.sourceCommit ? { sourceCommit: normalized.sourceCommit } : {}) } } };
  }
}
