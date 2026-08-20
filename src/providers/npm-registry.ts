import type { Evidence, PackageSupplyChain } from "../domain/risk.ts";
import { UpstreamHttp } from "./http.ts";

type NpmVersion = {
  deprecated?: string;
  repository?: string | { url?: string };
  scripts?: Record<string, string>;
  dist?: { integrity?: string; signatures?: unknown[] };
  maintainers?: Array<{ name?: string }>;
  _npmUser?: { name?: string };
};

function repositoryUrl(repository: NpmVersion["repository"]): string | undefined {
  if (typeof repository === "string") return repository;
  return repository?.url;
}

export class NpmRegistryProvider {
  constructor(private readonly http: UpstreamHttp) {}

  async packageMetadata(name: string, version: string): Promise<{ signals: PackageSupplyChain; evidence: Evidence }> {
    const encodedName = encodeURIComponent(name);
    const data = await this.http.json<NpmVersion>(
      `https://registry.npmjs.org/${encodedName}/${encodeURIComponent(version)}`,
      { headers: { accept: "application/json" } }
    );
    const scripts = data.scripts ?? {};
    const lifecycle = ["preinstall", "install", "postinstall"];
    const signals: PackageSupplyChain = {
      registry: "npm",
      deprecated: typeof data.deprecated === "string" && data.deprecated.length > 0,
      hasInstallScript: lifecycle.some(name => typeof scripts[name] === "string" && scripts[name]!.length > 0),
      integrityPresent: typeof data.dist?.integrity === "string" && data.dist.integrity.length > 0,
      signatureCount: data.dist?.signatures?.length ?? 0,
      maintainerCount: data.maintainers?.length ?? 0,
      ...(data._npmUser?.name ? { publisher: data._npmUser.name } : {}),
      ...(repositoryUrl(data.repository) ? { repositoryUrl: repositoryUrl(data.repository)! } : {})
    };
    return {
      signals,
      evidence: {
        source: "npm Registry",
        kind: "package_supply_chain_metadata",
        observedAt: new Date().toISOString(),
        detail: { name, version, ...signals }
      }
    };
  }
}
