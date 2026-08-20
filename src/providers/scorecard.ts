import type { Evidence } from "../domain/risk.ts";
import { UpstreamHttp } from "./http.ts";

type ScorecardResponse = { score?: number; date?: string; repo?: { name?: string; commit?: string } };

export class ScorecardProvider {
  constructor(private readonly http: UpstreamHttp) {}

  async repository(owner: string, repo: string): Promise<{ score: number; evidence: Evidence }> {
    const encodedOwner = encodeURIComponent(owner);
    const encodedRepo = encodeURIComponent(repo);
    const data = await this.http.json<ScorecardResponse>(
      `https://api.scorecard.dev/projects/github.com/${encodedOwner}/${encodedRepo}`,
      {}
    );
    if (typeof data.score !== "number") throw new Error("upstream response did not include a score");
    const score = data.score;
    return {
      score,
      evidence: {
        source: "OpenSSF Scorecard",
        kind: "repository_security_practices",
        observedAt: new Date().toISOString(),
        detail: { owner, repo, score, commit: data.repo?.commit ?? null }
      }
    };
  }
}
