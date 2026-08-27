import { describe, expect, test } from "bun:test";
import { CachedLoader, type Cache } from "../src/data/cache.ts";
import { GitHubRepositoryProvider } from "../src/providers/github-repository.ts";
import { UpstreamHttpError } from "../src/providers/http.ts";
import { ScorecardProvider, type ScorecardRepositoryIdentity } from "../src/providers/scorecard.ts";

const canonicalIdentity: ScorecardRepositoryIdentity = {
  repository: "github.com/riyannode/omni",
  resolvedCommitSha: "0123456789abcdef0123456789abcdef01234567"
};

function scorecardResponse(overrides: Record<string, unknown> = {}) {
  return {
    date: "2026-08-27T00:00:00Z",
    repo: { name: canonicalIdentity.repository, commit: canonicalIdentity.resolvedCommitSha },
    scorecard: { version: "v5.5.0", commit: "abcdef0123456789abcdef0123456789abcdef01" },
    score: 9.5,
    checks: [],
    ...overrides
  };
}

function cacheSpy() {
  const values = new Map<string, string>();
  const calls: Array<{ key: string; ttlSeconds: number }> = [];
  const cache: Cache = {
    async get(key) { return values.get(key) ?? null; },
    async set(key, value, ttlSeconds) { calls.push({ key, ttlSeconds }); values.set(key, value); }
  };
  return { cache, calls };
}

describe("ScorecardProvider", () => {
  test("returns available latest evidence with canonical identity and explicit mode", async () => {
    const urls: string[] = [];
    const provider = new ScorecardProvider({
      async json(url: string) { urls.push(url); return scorecardResponse(); }
    } as never);

    const result = await provider.repository(canonicalIdentity);

    expect(result.status).toBe("available");
    if (result.status !== "available") throw new Error("expected available Scorecard result");
    expect(result.score).toBe(9.5);
    expect(urls).toEqual(["https://api.scorecard.dev/projects/github.com/riyannode/omni"]);
    expect(result.evidence.detail).toMatchObject({
      repository: canonicalIdentity.repository,
      mode: "latest",
      score: 9.5,
      scorecardCommit: canonicalIdentity.resolvedCommitSha,
      commitMatch: "not_checked"
    });
    expect(result.evidence.detail).not.toHaveProperty("resolvedCommitSha");
  });

  test("maps a proper repository 404 to not_indexed without an outage claim", async () => {
    const provider = new ScorecardProvider({
      async json() { throw new UpstreamHttpError(404, "api.scorecard.dev"); }
    } as never);

    const result = await provider.repository(canonicalIdentity);

    expect(result).toEqual({
      status: "not_indexed",
      diagnostic: {
        httpStatus: 404,
        host: "api.scorecard.dev",
        mode: "latest",
        repository: canonicalIdentity.repository,
        reason: "missing_result"
      }
    });
  });

  test("rejects a 200 response for a different repository", async () => {
    const provider = new ScorecardProvider({
      async json() { return scorecardResponse({ repo: { name: "github.com/other/repository", commit: canonicalIdentity.resolvedCommitSha } }); }
    } as never);

    const result = await provider.repository(canonicalIdentity);

    expect(result.status).toBe("error");
    if (result.status === "available") throw new Error("expected Scorecard identity error");
    expect(result.diagnostic).toMatchObject({
      host: "api.scorecard.dev",
      mode: "latest",
      repository: canonicalIdentity.repository,
      returnedRepository: "github.com/other/repository",
      reason: "repository_identity_mismatch"
    });
  });

  test("rejects a commit-mode response with a different commit", async () => {
    const urls: string[] = [];
    const provider = new ScorecardProvider({
      async json(url: string) { urls.push(url); return scorecardResponse({ repo: { name: canonicalIdentity.repository, commit: "fedcba9876543210fedcba9876543210fedcba98" } }); }
    } as never);

    const result = await provider.repository(canonicalIdentity, "commit");

    expect(urls).toEqual([`${"https://api.scorecard.dev/projects/github.com/riyannode/omni"}?commit=${canonicalIdentity.resolvedCommitSha}`]);
    expect(result.status).toBe("error");
    if (result.status === "available") throw new Error("expected Scorecard identity error");
    expect(result.diagnostic).toMatchObject({
      mode: "commit",
      expectedCommit: canonicalIdentity.resolvedCommitSha,
      returnedCommit: "fedcba9876543210fedcba9876543210fedcba98",
      reason: "commit_mismatch"
    });
  });

  test("classifies malformed, timeout, 400, and 422 responses distinctly", async () => {
    const malformed = new ScorecardProvider({ async json() { return { score: "9.5" }; } } as never);
    const timeout = new ScorecardProvider({ async json() { throw new DOMException("timed out", "TimeoutError"); } } as never);
    const badRequest = new ScorecardProvider({ async json() { throw new UpstreamHttpError(400, "api.scorecard.dev"); } } as never);
    const unprocessable = new ScorecardProvider({ async json() { throw new UpstreamHttpError(422, "api.scorecard.dev"); } } as never);

    await expect(malformed.repository(canonicalIdentity)).resolves.toMatchObject({ status: "error", diagnostic: { reason: "malformed_response" } });
    await expect(timeout.repository(canonicalIdentity)).resolves.toMatchObject({ status: "unavailable", diagnostic: { reason: "timeout" } });
    await expect(badRequest.repository(canonicalIdentity)).resolves.toMatchObject({ status: "error", diagnostic: { httpStatus: 400 } });
    await expect(unprocessable.repository(canonicalIdentity)).resolves.toMatchObject({ status: "error", diagnostic: { httpStatus: 422 } });
  });

  test("uses a separate 600-second latest cache and commit cache", async () => {
    const { cache, calls } = cacheSpy();
    const urls: string[] = [];
    const provider = new ScorecardProvider({
      async json(url: string) { urls.push(url); return scorecardResponse(); }
    } as never, new CachedLoader(cache));

    await provider.repository(canonicalIdentity);
    await provider.repository(canonicalIdentity);
    await provider.repository(canonicalIdentity, "commit");

    expect(urls).toHaveLength(2);
    expect(urls[0]).not.toContain("commit=");
    expect(urls[1]).toContain(`commit=${canonicalIdentity.resolvedCommitSha}`);
    expect(calls).toEqual([
      { key: "scorecard:v1:github.com/riyannode/omni:rest:latest", ttlSeconds: 600 },
      { key: "scorecard:v1:github.com/riyannode/omni:rest:commit:0123456789abcdef0123456789abcdef01234567", ttlSeconds: 600 }
    ]);
  });
});

describe("GitHub repository identity", () => {
  test("normalizes .git and uses GitHub full_name rather than caller casing", async () => {
    const calls: string[] = [];
    const http = {
      async request(url: string | URL) {
        const target = String(url);
        calls.push(target);
        const responses: Record<string, unknown> = {
          "https://api.github.com/repos/RiyanNode/Omni": { full_name: "riyannode/omni", default_branch: "main" },
          "https://api.github.com/repos/riyannode/omni/commits/main": { sha: canonicalIdentity.resolvedCommitSha, commit: { tree: { sha: "abcdef0123456789abcdef0123456789abcdef01" } } }
        };
        return new Response(JSON.stringify(responses[target] ?? { message: "not found" }), { status: responses[target] ? 200 : 404 });
      }
    };

    const identity = await new GitHubRepositoryProvider(http as never).resolve("RiyanNode", "Omni.git");

    expect(identity.repository).toBe("github.com/riyannode/omni");
    expect(calls).toEqual([
      "https://api.github.com/repos/RiyanNode/Omni",
      "https://api.github.com/repos/riyannode/omni/commits/main"
    ]);
  });

  test("rejects GitHub metadata for a different repository", async () => {
    const http = {
      async request() {
        return new Response(JSON.stringify({ full_name: "other/repository", default_branch: "main" }), { status: 200 });
      }
    };

    await expect(new GitHubRepositoryProvider(http as never).resolve("acme", "demo")).rejects.toThrow("github_repository_identity_mismatch");
  });
});
