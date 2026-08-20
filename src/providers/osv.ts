import type { Evidence, RiskLevel, VulnerabilityFinding } from "../domain/risk.ts";
import { UpstreamHttp } from "./http.ts";

type OsvVuln = {
  id: string;
  modified?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
  ecosystem_specific?: { severity?: string };
};
type OsvResponse = { vulns?: OsvVuln[] };

function normalizeSeverity(value?: string): RiskLevel {
  const v = value?.toLowerCase();
  if (v === "moderate") return "medium";
  if (v === "critical" || v === "high" || v === "medium" || v === "low") return v;
  return "unknown";
}

export class OsvProvider {
  constructor(private readonly http: UpstreamHttp) {}

  async packageVulnerabilities(ecosystem: string, name: string, version: string): Promise<{ findings: VulnerabilityFinding[]; evidence: Evidence[] }> {
    const body = { package: { ecosystem, name }, version };
    const data = await this.http.json<OsvResponse>("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });

    const findings = (data.vulns ?? []).map(v => ({
      id: v.id,
      severity: normalizeSeverity(v.database_specific?.severity ?? v.ecosystem_specific?.severity),
      knownExploited: false,
      aliases: v.aliases ?? []
    }));
    return {
      findings,
      evidence: [{
        source: "OSV",
        kind: "package_vulnerabilities",
        observedAt: new Date().toISOString(),
        detail: { ecosystem, name, version, vulnerabilityIds: findings.map(v => v.id) }
      }]
    };
  }
}
