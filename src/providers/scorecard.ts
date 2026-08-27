import type { Evidence } from "../domain/risk.ts";
import { CachedLoader } from "../data/cache.ts";
import { UpstreamHttp, UpstreamHttpError } from "./http.ts";

const SCORECARD_HOST = "api.scorecard.dev";
const SCORECARD_PROVIDER_CACHE_VERSION = "v1";
export const SCORECARD_CACHE_TTL_SECONDS = 600;
const SHA1 = /^[0-9a-f]{40}$/i;
const REPOSITORY = /^github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/;

export type ScorecardMode = "latest" | "commit";
export type ScorecardRepositoryIdentity = { repository: string; resolvedCommitSha?: string };
type ScorecardResponse = { score?: unknown; date?: unknown; repo?: { name?: unknown; commit?: unknown }; scorecard?: { version?: unknown; commit?: unknown } };

export type ScorecardDiagnostic = {
  httpStatus?: number;
  host: string;
  mode: ScorecardMode;
  repository: string;
  returnedRepository?: string;
  expectedCommit?: string;
  returnedCommit?: string;
  reason: string;
};

export type ScorecardProviderResult =
  | { status: "available"; score: number; evidence: Evidence }
  | { status: "not_indexed" | "unavailable" | "error"; diagnostic: ScorecardDiagnostic };

function bounded(value: unknown): string | undefined {
  return typeof value === "string" && value.length <= 256 ? value : undefined;
}

function identityParts(repository: string): { owner: string; repo: string } {
  const match = repository.match(REPOSITORY);
  if (!match || match[2]!.toLowerCase().endsWith(".git")) throw new Error("scorecard_repository_identity_invalid");
  return { owner: match[1]!, repo: match[2]! };
}

function diagnostic(identity: ScorecardRepositoryIdentity, mode: ScorecardMode, reason: string, extra: Partial<ScorecardDiagnostic> = {}): ScorecardDiagnostic {
  return { host: SCORECARD_HOST, mode, repository: bounded(identity.repository) ?? "invalid", reason, ...(mode === "commit" && identity.resolvedCommitSha && SHA1.test(identity.resolvedCommitSha) ? { expectedCommit: identity.resolvedCommitSha } : {}), ...extra };
}

function cacheKey(identity: ScorecardRepositoryIdentity, mode: ScorecardMode): string {
  return mode === "latest"
    ? `scorecard:${SCORECARD_PROVIDER_CACHE_VERSION}:${identity.repository}:rest:latest`
    : `scorecard:${SCORECARD_PROVIDER_CACHE_VERSION}:${identity.repository}:rest:commit:${identity.resolvedCommitSha}`;
}

export class ScorecardProvider {
  constructor(private readonly http: UpstreamHttp, private readonly cache?: CachedLoader) {}

  async repository(identity: ScorecardRepositoryIdentity, mode: ScorecardMode = "latest"): Promise<ScorecardProviderResult> {
    let parts: { owner: string; repo: string };
    try {
      parts = identityParts(identity.repository);
    } catch {
      return { status: "error", diagnostic: diagnostic(identity, mode, "repository_identity_invalid") };
    }
    if (mode === "commit" && (!identity.resolvedCommitSha || !SHA1.test(identity.resolvedCommitSha))) {
      return { status: "error", diagnostic: diagnostic(identity, mode, "commit_identity_invalid") };
    }
    const load = () => this.load(identity, parts, mode);
    if (!this.cache) return load();
    return this.cache.getOrLoad(cacheKey(identity, mode), SCORECARD_CACHE_TTL_SECONDS, load);
  }

  private async load(identity: ScorecardRepositoryIdentity, parts: { owner: string; repo: string }, mode: ScorecardMode): Promise<ScorecardProviderResult> {
    const baseUrl = `https://${SCORECARD_HOST}/projects/github.com/${encodeURIComponent(parts.owner)}/${encodeURIComponent(parts.repo)}`;
    const url = mode === "commit" ? `${baseUrl}?commit=${encodeURIComponent(identity.resolvedCommitSha!)}` : baseUrl;
    let data: ScorecardResponse;
    try {
      data = await this.http.json<ScorecardResponse>(url, {});
    } catch (error) {
      if (error instanceof UpstreamHttpError) {
        if (error.status === 404) return { status: "not_indexed", diagnostic: diagnostic(identity, mode, "missing_result", { httpStatus: error.status }) };
        if (error.status === 408 || error.status === 429 || error.status >= 500) return { status: "unavailable", diagnostic: diagnostic(identity, mode, "upstream_unavailable", { httpStatus: error.status }) };
        return { status: "error", diagnostic: diagnostic(identity, mode, "http_error", { httpStatus: error.status }) };
      }
      if (error instanceof DOMException && (error.name === "TimeoutError" || error.name === "AbortError")) return { status: "unavailable", diagnostic: diagnostic(identity, mode, "timeout") };
      return { status: "unavailable", diagnostic: diagnostic(identity, mode, "network_error") };
    }

    const returnedRepository = bounded(data.repo?.name);
    const returnedCommit = bounded(data.repo?.commit);
    const scorecardDate = bounded(data.date);
    const scorecardVersion = bounded(data.scorecard?.version);
    const scorecardEngineCommit = bounded(data.scorecard?.commit);
    if (returnedRepository === undefined) {
      return { status: "error", diagnostic: diagnostic(identity, mode, "malformed_response", { ...(returnedCommit ? { returnedCommit } : {}) }) };
    }
    if (returnedRepository !== identity.repository) {
      return { status: "error", diagnostic: diagnostic(identity, mode, "repository_identity_mismatch", { returnedRepository, ...(returnedCommit ? { returnedCommit } : {}) }) };
    }
    if (returnedCommit === undefined || !SHA1.test(returnedCommit) || typeof data.score !== "number" || !Number.isFinite(data.score) || data.score < 0 || data.score > 10) {
      return { status: "error", diagnostic: diagnostic(identity, mode, "malformed_response", { returnedRepository, ...(returnedCommit ? { returnedCommit } : {}) }) };
    }
    if (mode === "commit" && returnedCommit !== identity.resolvedCommitSha) {
      return { status: "error", diagnostic: diagnostic(identity, mode, "commit_mismatch", { returnedCommit }) };
    }

    const observedAt = new Date();
    return {
      status: "available",
      score: data.score,
      evidence: {
        source: "OpenSSF Scorecard",
        kind: "repository_security_practices",
        observedAt: observedAt.toISOString(),
        expiresAt: new Date(observedAt.getTime() + SCORECARD_CACHE_TTL_SECONDS * 1000).toISOString(),
        detail: {
          repository: identity.repository,
          score: data.score,
          mode,
          scorecardCommit: returnedCommit,
          scorecardDate: scorecardDate ?? null,
          scorecardVersion: scorecardVersion ?? null,
          scorecardEngineCommit: scorecardEngineCommit ?? null,
          ...(mode === "commit" && identity.resolvedCommitSha ? { resolvedCommitSha: identity.resolvedCommitSha } : {}),
          commitMatch: mode === "commit" ? true : "not_checked"
        }
      }
    };
  }
}
