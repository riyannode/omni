import type { DependencyObservation, Evidence, ExactDependencyCoordinate, ProvenanceObservation } from "../domain/risk.ts";
import type { UpstreamHttp } from "./http.ts";

const MAX_VERSION_RESPONSE_BYTES = 512 * 1024;
const MAX_GRAPH_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_GRAPH_NODES = 20_000;

type Http = Pick<UpstreamHttp, "boundedJson">;
type Expected = { repository?: string; commit?: string };
type Attestation = { verified?: boolean; sourceRepository?: string; commit?: string; url?: string };
type GraphNode = { errors?: unknown[] };
type ResponseData = { licenses?: string[]; advisoryKeys?: Array<{ id?: string }>; relatedProjects?: Array<{ projectKey?: { id?: string }; relationType?: string; relationProvenance?: string }>; slsaProvenances?: Attestation[]; attestations?: Attestation[] };
type GraphData = { error?: unknown; nodes?: GraphNode[] };

const MAX_GRAPH_ERROR_DIAGNOSTICS = 5;
const MAX_DIAGNOSTIC_CHARS = 120;

// Canonical repository identity keeps the host/path separator: "github.com/acme/demo".
function repository(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try { const url = value.includes("://") ? new URL(value) : new URL(`https://${value}`); return `${url.hostname.toLowerCase()}/${url.pathname.replace(/^\//, "").replace(/\.git$/, "").replace(/\/$/, "")}`; } catch { return undefined; }
}

function diagnosticText(value: unknown): string {
  const text = typeof value === "string" ? value : JSON.stringify(value) ?? "";
  return text.slice(0, MAX_DIAGNOSTIC_CHARS);
}

export function normalizeProvenance(attestation: Attestation | undefined, expected: Expected = {}): Omit<ProvenanceObservation, "package" | "source"> {
  if (!attestation) return { state: "UNAVAILABLE" };
  const sourceRepository = repository(attestation.sourceRepository); const sourceCommit = attestation.commit;
  if (attestation.verified !== true) return { state: "PRESENT_UNVERIFIED", ...(sourceRepository ? { sourceRepository } : {}), ...(sourceCommit ? { sourceCommit } : {}), ...(attestation.url ? { attestationUrl: attestation.url } : {}) };
  if (!sourceRepository) return { state: "ERROR", ...(sourceCommit ? { sourceCommit } : {}), ...(attestation.url ? { attestationUrl: attestation.url } : {}) };
  const expectedRepository = repository(expected.repository);
  if (expectedRepository && expectedRepository !== sourceRepository) return { state: "VERIFIED_SOURCE_MISMATCH", sourceRepository, ...(sourceCommit ? { sourceCommit } : {}), expectedSourceMatches: false, ...(attestation.url ? { attestationUrl: attestation.url } : {}) };
  if (sourceCommit && expected.commit && expected.commit.toLowerCase() !== sourceCommit.toLowerCase()) return { state: "VERIFIED_COMMIT_MISMATCH", sourceRepository, sourceCommit, ...(expectedRepository ? { expectedSourceMatches: true } : {}), expectedCommitMatches: false, ...(attestation.url ? { attestationUrl: attestation.url } : {}) };
  // Fail closed: a cryptographically verified attestation without a source commit is
  // never claimed as VERIFIED against an expected commit. Attestation verification and
  // expected-commit matching are separate facts; without the commit the match is unknown.
  if (expected.commit && !sourceCommit) return { state: "VERIFIED_COMMIT_UNCONFIRMED", sourceRepository, ...(expectedRepository ? { expectedSourceMatches: true } : {}), expectedCommitMatches: false, ...(attestation.url ? { attestationUrl: attestation.url } : {}) };
  return { state: "VERIFIED", sourceRepository, ...(sourceCommit ? { sourceCommit } : {}), ...(expectedRepository ? { expectedSourceMatches: true } : {}), ...(expected.commit && sourceCommit ? { expectedCommitMatches: true } : {}), ...(attestation.url ? { attestationUrl: attestation.url } : {}) };
}

function expectation(data: ResponseData): Expected {
  const candidates = (data.relatedProjects ?? []).filter(item => item.relationType === "SOURCE_REPO" && item.relationProvenance !== "UNVERIFIED_METADATA").map(item => repository(item.projectKey?.id)).filter((item): item is string => item !== undefined);
  const candidate = candidates[0];
  return candidate === undefined ? {} : { repository: candidate };
}

export class DepsDevProvider {
  constructor(private readonly http: Http) {}

  async packageVersion(coordinate: ExactDependencyCoordinate, expected: Expected = {}): Promise<{ observation: DependencyObservation; evidence: Evidence }> {
    const base = `https://api.deps.dev/v3/systems/${coordinate.ecosystem}/packages/${encodeURIComponent(coordinate.name)}/versions/${encodeURIComponent(coordinate.version)}`;
    const data = await this.http.boundedJson<ResponseData>(base, MAX_VERSION_RESPONSE_BYTES);
    let graph: { checked: boolean; nodeCount: number; error?: string };
    try {
      const graphData = await this.http.boundedJson<GraphData>(`${base}:dependencies`, MAX_GRAPH_RESPONSE_BYTES);
      const nodeCount = Array.isArray(graphData.nodes) ? graphData.nodes.length : 0;
      // Official deps.dev semantics: a non-empty top-level "error" or per-node
      // errors[] mean the dependency graph is incomplete/incorrect, so it is never
      // reported as checked. An empty-string error field means no error.
      const diagnostics: string[] = [];
      if (typeof graphData.error === "string" && graphData.error.trim()) diagnostics.push(diagnosticText(graphData.error));
      else if (graphData.error !== undefined && graphData.error !== null && typeof graphData.error !== "string") diagnostics.push(diagnosticText(graphData.error));
      if (Array.isArray(graphData.nodes)) {
        for (const node of graphData.nodes) {
          for (const nodeError of Array.isArray(node?.errors) ? node.errors : []) diagnostics.push(diagnosticText(nodeError));
        }
      }
      if (nodeCount > MAX_GRAPH_NODES) { graph = { checked: false, nodeCount: 0, error: "deps_graph_node_limit" }; }
      else if (diagnostics.length > 0) { graph = { checked: false, nodeCount, error: [...new Set(diagnostics)].slice(0, MAX_GRAPH_ERROR_DIAGNOSTICS).join("; ") }; }
      else graph = { checked: true, nodeCount };
    } catch (error) { graph = { checked: false, nodeCount: 0, error: error instanceof Error ? error.message : "unknown error" }; }
    const normalized = normalizeProvenance(data.slsaProvenances?.[0] ?? data.attestations?.[0], expected.repository || expected.commit ? expected : expectation(data));
    const licenses = [...new Set((data.licenses ?? []).filter((item): item is string => typeof item === "string"))].sort();
    const advisories = [...new Set((data.advisoryKeys ?? []).flatMap(item => typeof item.id === "string" ? [item.id] : []))].sort();
    const provenance = [{ package: coordinate, source: "deps.dev" as const, ...normalized }];
    const observation: DependencyObservation = { coordinate, licenses, advisoryIds: advisories, graph, provenance };
    return { observation, evidence: { source: "deps.dev", kind: "package_dependency_provenance", observedAt: new Date().toISOString(), detail: { ecosystem: coordinate.ecosystem, name: coordinate.name, version: coordinate.version, licenses, advisoryIds: advisories, provenanceState: normalized.state, ...(normalized.sourceRepository ? { sourceRepository: normalized.sourceRepository } : {}), ...(normalized.sourceCommit ? { sourceCommit: normalized.sourceCommit } : {}) } } };
  }
}
