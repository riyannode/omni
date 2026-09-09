import type { ExactDependencyCoordinate, RepositoryEvidence, RepositorySecurityFile, UnresolvedDependency } from "../domain/risk.ts";
import type { UpstreamHttp } from "./http.ts";
import { isDependencyResolutionPath, resolveRepositoryDependencies } from "./dependency-resolution.ts";

const MAX_TREE_ENTRIES = 10_000;
const MAX_FILES = 32;
const MAX_FILE_BYTES = 128 * 1024;
const MAX_TOTAL_BYTES = 512 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const GITHUB_RAW_THRESHOLD_BYTES = 1_000_000;
export const MAX_DEPENDENCY_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_DEPENDENCY_TOTAL_BYTES = 8 * 1024 * 1024;
export const MAX_DEPENDENCY_FILES = 128;

export type RepositoryIdentity = {
  repository: string;
  requestedRef: string;
  resolvedCommitSha: string;
  rootTreeSha: string;
};

const REPOSITORY_PART = /^[A-Za-z0-9_.-]+$/;

type Http = Pick<UpstreamHttp, "request">;
type TreeEntry = { path?: string; type?: string; sha?: string; size?: number };

function normalizedRepoName(repo: string): string {
  const normalized = repo.replace(/\.git$/i, "");
  if (!REPOSITORY_PART.test(normalized)) throw new Error("github_repository_identity_invalid");
  return normalized;
}

function canonicalParts(repository: string): { owner: string; repo: string } {
  const parts = repository.split("/");
  if (parts.length !== 3 || parts[0] !== "github.com" || !REPOSITORY_PART.test(parts[1]!) || !REPOSITORY_PART.test(parts[2]!) || parts[2]!.toLowerCase().endsWith(".git")) {
    throw new Error("github_repository_identity_invalid");
  }
  return { owner: parts[1]!, repo: parts[2]! };
}

async function boundedBytes(response: Response, maximumBytes: number): Promise<Uint8Array> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) > maximumBytes) throw new Error("github_response_oversized");
  if (!response.body) throw new Error("github_response_missing_body");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = []; let total = 0;
  while (true) {
    const value = await reader.read();
    if (value.done) break;
    total += value.value.byteLength;
    if (total > maximumBytes) { await reader.cancel(); throw new Error("github_response_oversized"); }
    chunks.push(value.value);
  }
  const joined = new Uint8Array(total); let offset = 0;
  for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.byteLength; }
  return joined;
}

async function body(response: Response): Promise<string> {
  return new TextDecoder("utf-8", { fatal: true }).decode(await boundedBytes(response, MAX_RESPONSE_BYTES));
}

function failure(response: Response): string {
  return response.status === 403 || response.status === 429 ? "github_rate_limited" : `github_http_${response.status}`;
}

async function json<T>(http: Http, url: string, headers: HeadersInit): Promise<T> {
  const response = await http.request(url, { headers, redirect: "error" });
  if (!response.ok) throw new Error(failure(response));
  return JSON.parse(await body(response)) as T;
}

function category(path: string): RepositorySecurityFile["category"] | undefined {
  const value = path.toLowerCase();
  if (/(^|\/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|pyproject\.toml|cargo\.toml|cargo\.lock|go\.mod|go\.sum|vendor\/modules\.txt|pnpm-lock\.yaml|pnpm-workspace\.yaml|yarn\.lock|bun\.lock)$/.test(value) || /(^|\/)requirements[^/]*\.txt$/.test(value)) return "manifest";
  if (/^\.github\/workflows\/.*\.ya?ml$/.test(value)) return "workflow";
  if (/(^|\/)dockerfile[^/]*$/.test(value) || /(^|\/)(docker-)?compose\.ya?ml$/.test(value)) return "build";
  if (/(^|\/)(action\.ya?ml)$/.test(value) || value.includes("release") || value.includes("publish")) return "release";
  return undefined;
}

function downloadExecute(value: string): boolean { return /(?:curl|wget|invoke-webrequest|\biwr\b)[^\n]*(?:\||&&|;)\s*(?:sh|bash|zsh|pwsh|powershell|node)\b/i.test(value); }

function inspect(path: string, kind: RepositorySecurityFile["category"], value: string): string[] {
  const findings = new Set<string>();
  if (downloadExecute(value)) findings.add("DOWNLOAD_EXECUTE_PATTERN");
  if (kind === "workflow") {
    for (const item of value.matchAll(/^\s*(?:-\s*)?uses:\s*[^\s#]+@([^\s#]+)\s*$/gmi)) if (!/^[a-f0-9]{40}$/i.test(item[1]!)) findings.add("MUTABLE_GITHUB_ACTION_REF");
    if (/^\s*permissions:\s*(?:write-all|\{[^}]*\b\w+\s*:\s*write)/mi.test(value) || /^\s+\w[\w-]*:\s*write\s*$/mi.test(value)) findings.add("WORKFLOW_WRITE_PERMISSION");
  }
  if (path.toLowerCase().endsWith("package.json")) {
    try {
      const data = JSON.parse(value) as { scripts?: Record<string, unknown> };
      if (["preinstall", "install", "postinstall"].some(name => typeof data.scripts?.[name] === "string" && data.scripts[name]!.trim())) findings.add("INSTALL_LIFECYCLE_SCRIPT");
    } catch { findings.add("MALFORMED_MANIFEST"); }
  }
  return [...findings].sort();
}

async function decodedContent(http: Http, url: string, headers: HeadersInit, rawLimit?: number): Promise<Uint8Array> {
  if (rawLimit !== undefined) {
    const rawHeaders = new Headers(headers);
    rawHeaders.set("accept", "application/vnd.github.raw+json");
    const response = await http.request(url, { headers: rawHeaders, redirect: "error" });
    if (!response.ok) throw new Error(failure(response));
    return boundedBytes(response, rawLimit);
  }
  const data = await json<{ encoding?: string; content?: string }>(http, url, headers);
  if (data.encoding !== "base64" || typeof data.content !== "string") throw new Error("github_content_unsupported");
  return Buffer.from(data.content.replaceAll("\n", ""), "base64");
}

function textContent(bytes: Uint8Array): string {
  if (bytes.includes(0)) throw new Error("github_content_binary");
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

export class GitHubRepositoryProvider {
  constructor(private readonly http: Http, private readonly token?: string) {}

  private base(owner: string, repo: string): string { return `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(normalizedRepoName(repo))}`; }
  private headers(): Headers {
    const headers = new Headers({ accept: "application/vnd.github+json", "x-github-api-version": "2026-03-10" });
    if (this.token) headers.set("authorization", `Bearer ${this.token}`);
    return headers;
  }

  async resolve(owner: string, repo: string, requestedRef?: string): Promise<RepositoryIdentity> {
    const base = this.base(owner, repo); const headers = this.headers();
    const metadata = await json<{ full_name?: string; default_branch?: string }>(this.http, base, headers);
    if (typeof metadata.full_name !== "string") throw new Error("github_repository_identity_missing");
    const fullName = metadata.full_name.split("/");
    const normalizedRequestedRepo = normalizedRepoName(repo);
    if (fullName.length !== 2 || !REPOSITORY_PART.test(fullName[0]!) || !REPOSITORY_PART.test(fullName[1]!) || fullName[1]!.toLowerCase().endsWith(".git")) throw new Error("github_repository_identity_invalid");
    if (fullName[0]!.toLowerCase() !== owner.toLowerCase() || fullName[1]!.toLowerCase() !== normalizedRequestedRepo.toLowerCase()) throw new Error("github_repository_identity_mismatch");
    const canonicalRepository = `github.com/${metadata.full_name}`;
    const canonicalBase = this.base(fullName[0]!, fullName[1]!);
    const ref = requestedRef ?? metadata.default_branch;
    if (!ref) throw new Error("github_default_branch_missing");
    const commit = await json<{ sha?: string; commit?: { tree?: { sha?: string } } }>(this.http, `${canonicalBase}/commits/${encodeURIComponent(ref)}`, headers);
    const resolvedCommitSha = commit.sha; const rootTreeSha = commit.commit?.tree?.sha;
    if (typeof resolvedCommitSha !== "string" || typeof rootTreeSha !== "string" || !/^[a-f0-9]{40}$/i.test(resolvedCommitSha) || !/^[a-f0-9]{40}$/i.test(rootTreeSha)) throw new Error("github_commit_identity_invalid");
    return { repository: canonicalRepository, requestedRef: ref, resolvedCommitSha, rootTreeSha };
  }

  async collect(owner: string, repo: string, requestedRef?: string): Promise<RepositoryEvidence> {
    return this.collectResolved(owner, repo, await this.resolve(owner, repo, requestedRef));
  }

  async collectResolved(_owner: string, _repo: string, identity: RepositoryIdentity): Promise<RepositoryEvidence> {
    const parts = canonicalParts(identity.repository);
    const base = this.base(parts.owner, parts.repo); const headers = this.headers();
    const response = await json<{ truncated?: boolean; tree?: TreeEntry[] }>(this.http, `${base}/git/trees/${identity.rootTreeSha}?recursive=1`, headers);
    const limitations: string[] = [];
    const githubLimitations: string[] = [];
    const addGithubLimitation = (limitation: string): void => { limitations.push(limitation); githubLimitations.push(limitation); };
    if (response.truncated) addGithubLimitation("github_tree_truncated");
    const entries = (response.tree ?? []).filter((entry): entry is Required<TreeEntry> => typeof entry.path === "string" && entry.type === "blob" && typeof entry.sha === "string" && typeof entry.size === "number").sort((a, b) => a.path.localeCompare(b.path));
    if (entries.length > MAX_TREE_ENTRIES) addGithubLimitation("tree_entry_limit_reached");
    const candidates = entries.filter(entry => category(entry.path) !== undefined);
    if (candidates.length > MAX_FILES) addGithubLimitation("security_file_limit_reached");

    const dependencyCandidates = entries.filter(entry => isDependencyResolutionPath(entry.path));
    const dependencyAllowed = new Set(dependencyCandidates.slice(0, MAX_DEPENDENCY_FILES).map(entry => entry.path));
    let dependencyDiscoveryComplete = !Boolean(response.truncated) && entries.length <= MAX_TREE_ENTRIES && dependencyCandidates.length <= MAX_DEPENDENCY_FILES;
    const dependencyFiles = new Map<string, string>();
    let dependencyBytes = 0;
    const securityFiles: RepositorySecurityFile[] = [];
    let bytesInspected = 0;

    for (const [securityIndex, entry] of candidates.entries()) {
      const dependencyCandidate = isDependencyResolutionPath(entry.path) && dependencyAllowed.has(entry.path);
      const securityCandidate = securityIndex < MAX_FILES;
      if (!dependencyCandidate && !securityCandidate) continue;
      const kind = category(entry.path)!;
      const dependencyOversized = dependencyCandidate && entry.size > MAX_DEPENDENCY_FILE_BYTES;
      const securityOversized = securityCandidate && entry.size > MAX_FILE_BYTES;
      if (dependencyOversized) {
        dependencyDiscoveryComplete = false;
        limitations.push(`dependency_file_oversized:${entry.path}`);
      }
      if (securityOversized) {
        addGithubLimitation(`security_file_oversized:${entry.path}`);
        securityFiles.push({ path: entry.path, category: kind, status: "oversized", findings: [] });
      }
      const inspectSecurity = securityCandidate && !securityOversized;
      if (dependencyOversized || (!dependencyCandidate && !inspectSecurity)) continue;
      try {
        const bytes = await decodedContent(this.http, `${base}/contents/${encodeURIComponent(entry.path)}?ref=${identity.resolvedCommitSha}`, headers, dependencyCandidate && entry.size > GITHUB_RAW_THRESHOLD_BYTES ? MAX_DEPENDENCY_FILE_BYTES : undefined);
        if (dependencyCandidate && !dependencyOversized) {
          if (bytes.byteLength > MAX_DEPENDENCY_FILE_BYTES) {
            dependencyDiscoveryComplete = false;
            limitations.push(`dependency_file_oversized:${entry.path}`);
          } else if (dependencyBytes + bytes.byteLength > MAX_DEPENDENCY_TOTAL_BYTES) {
            dependencyDiscoveryComplete = false;
            limitations.push(`dependency_resolution_byte_budget_exceeded:${entry.path}`);
          } else if (bytes.includes(0)) {
            dependencyDiscoveryComplete = false;
            limitations.push(`dependency_file_binary:${entry.path}`);
          } else {
            dependencyFiles.set(entry.path, textContent(bytes));
            dependencyBytes += bytes.byteLength;
          }
        }
        if (!inspectSecurity) continue;
        if (bytes.byteLength > MAX_FILE_BYTES || bytesInspected + bytes.byteLength > MAX_TOTAL_BYTES) {
          addGithubLimitation(`security_file_oversized:${entry.path}`);
          securityFiles.push({ path: entry.path, category: kind, status: "oversized", findings: [] });
          continue;
        }
        if (bytes.includes(0)) {
          addGithubLimitation(`security_file_binary:${entry.path}`);
          securityFiles.push({ path: entry.path, category: kind, status: "binary", findings: [] });
          continue;
        }
        const text = textContent(bytes);
        bytesInspected += bytes.byteLength;
        securityFiles.push({ path: entry.path, category: kind, status: "inspected", findings: inspect(entry.path, kind, text) });
      } catch (error) {
        const message = error instanceof Error ? error.message : "github_content_error";
        if (dependencyCandidate) {
          dependencyDiscoveryComplete = false;
          limitations.push(`dependency_file_unavailable:${entry.path}`);
        }
        if (inspectSecurity) {
          addGithubLimitation(`${message}:${entry.path}`);
          securityFiles.push({ path: entry.path, category: kind, status: "unsupported", findings: [] });
        }
      }
    }
    if (dependencyCandidates.length > MAX_DEPENDENCY_FILES) limitations.push(`dependency_file_limit_reached:${MAX_DEPENDENCY_FILES}_of_${dependencyCandidates.length}`);

    const resolved = resolveRepositoryDependencies({ files: dependencyFiles, candidatePaths: dependencyCandidates.map(entry => entry.path), manifestDiscoveryComplete: dependencyDiscoveryComplete });
    limitations.push(...resolved.limitations);
    if (resolved.unresolved.length > 0) limitations.push("dependency_versions_unresolved");
    const dependencyEvidence = { exact: resolved.exact, unresolved: resolved.unresolved, resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } };
    return {
      target: { repository: identity.repository, requestedRef: identity.requestedRef, resolvedCommitSha: identity.resolvedCommitSha },
      githubCollection: { status: githubLimitations.length === 0 ? "complete" : "partial", limitations: [...new Set(githubLimitations)].sort(), sourceErrors: [] },
      securityFiles,
      dependencies: dependencyEvidence,
      dependencyObservations: [],
      dependencyVulnerabilities: { status: "NOT_CHECKED", packagesInspected: [], findings: [], maliciousPackageObservations: [], cisaKev: { status: "NOT_QUERIED", correlatableCveIds: [], matchedCveIds: [] }, errors: [], limitations: [] },
      dependencyThreatIntel: { status: "NOT_CHECKED", packagesInspected: [], findings: [], errors: [], limitations: [] },
      dependencyResolution: resolved.metadata,
      coverage: { status: limitations.length === 0 ? "complete" : "partial", treeEntriesInspected: Math.min(entries.length, MAX_TREE_ENTRIES), filesInspected: securityFiles.filter(file => file.status === "inspected").length, bytesInspected, limitations: [...new Set(limitations)].sort() },
      sourceErrors: []
    };
  }
}
