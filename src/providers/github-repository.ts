import type { ExactDependencyCoordinate, RepositoryEvidence, RepositorySecurityFile, UnresolvedDependency } from "../domain/risk.ts";
import type { UpstreamHttp } from "./http.ts";

const MAX_TREE_ENTRIES = 10_000;
const MAX_FILES = 32;
const MAX_FILE_BYTES = 128 * 1024;
const MAX_TOTAL_BYTES = 512 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

type Http = Pick<UpstreamHttp, "request">;
type TreeEntry = { path?: string; type?: string; sha?: string; size?: number };
type PackageLock = { packages?: Record<string, { version?: string }>; dependencies?: Record<string, { version?: string }> };

async function body(response: Response): Promise<string> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) > MAX_RESPONSE_BYTES) throw new Error("github_response_oversized");
  if (!response.body) throw new Error("github_response_missing_body");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = []; let total = 0;
  while (true) {
    const value = await reader.read();
    if (value.done) break;
    total += value.value.byteLength;
    if (total > MAX_RESPONSE_BYTES) { await reader.cancel(); throw new Error("github_response_oversized"); }
    chunks.push(value.value);
  }
  const joined = new Uint8Array(total); let offset = 0;
  for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder("utf-8", { fatal: true }).decode(joined);
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
  if (/(^|\/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|pyproject\.toml|cargo\.toml|cargo\.lock|go\.mod|go\.sum|pnpm-lock\.yaml|yarn\.lock|bun\.lock)$/.test(value) || /(^|\/)requirements[^/]*\.txt$/.test(value)) return "manifest";
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
  if (path.endsWith("package.json")) {
    try {
      const data = JSON.parse(value) as { scripts?: Record<string, unknown> };
      if (["preinstall", "install", "postinstall"].some(name => typeof data.scripts?.[name] === "string" && data.scripts[name]!.trim())) findings.add("INSTALL_LIFECYCLE_SCRIPT");
    } catch { findings.add("MALFORMED_MANIFEST"); }
  }
  return [...findings].sort();
}

function declarations(value: string): Map<string, string> {
  try {
    const data = JSON.parse(value) as Record<string, Record<string, string> | undefined>;
    const result = new Map<string, string>();
    for (const group of [data.dependencies, data.devDependencies, data.optionalDependencies, data.peerDependencies]) for (const [name, version] of Object.entries(group ?? {})) if (typeof version === "string") result.set(name, version);
    return result;
  } catch { return new Map(); }
}

function exactVersion(value: string | undefined): value is string { return typeof value === "string" && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(value); }

function bunLockVersion(value: string, name: string): string | undefined {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = value.match(new RegExp(`"${escaped}"\\s*:\\s*\\["${escaped}@([^"]+)"`));
  return match?.[1];
}

function dependencies(files: Map<string, string>): { exact: ExactDependencyCoordinate[]; unresolved: UnresolvedDependency[] } {
  const declared = new Map([...files.entries()].filter(([path]) => path.endsWith("package.json")).flatMap(([, value]) => [...declarations(value)]));
  if (declared.size === 0) return { exact: [], unresolved: [] };
  const lock = [...files.entries()].find(([path]) => path.endsWith("package-lock.json") || path.endsWith("npm-shrinkwrap.json"));
  const bunLock = [...files.entries()].find(([path]) => path.endsWith("bun.lock"));
  if (!lock && bunLock) {
    const exact: ExactDependencyCoordinate[] = []; const unresolved: UnresolvedDependency[] = [];
    for (const [name, requirement] of declared) {
      const version = bunLockVersion(bunLock[1], name);
      if (exactVersion(version)) exact.push({ ecosystem: "NPM", name, version, sourcePath: bunLock[0] }); else unresolved.push({ ecosystem: "NPM", name, requirement });
    }
    return { exact: exact.sort((a, b) => a.name.localeCompare(b.name)), unresolved: unresolved.sort((a, b) => a.name.localeCompare(b.name)) };
  }
  if (!lock) return { exact: [], unresolved: [...declared].map(([name, requirement]) => ({ ecosystem: "NPM" as const, name, requirement })).sort((a, b) => a.name.localeCompare(b.name)) };
  try {
    const data = JSON.parse(lock[1]) as PackageLock; const exact: ExactDependencyCoordinate[] = []; const unresolved: UnresolvedDependency[] = [];
    for (const [name, requirement] of declared) {
      const version = data.packages?.[`node_modules/${name}`]?.version ?? data.dependencies?.[name]?.version;
      if (exactVersion(version)) exact.push({ ecosystem: "NPM", name, version, sourcePath: lock[0] }); else unresolved.push({ ecosystem: "NPM", name, requirement });
    }
    return { exact: exact.sort((a, b) => a.name.localeCompare(b.name)), unresolved: unresolved.sort((a, b) => a.name.localeCompare(b.name)) };
  } catch { return { exact: [], unresolved: [...declared].map(([name, requirement]) => ({ ecosystem: "NPM", name, requirement })) }; }
}

export class GitHubRepositoryProvider {
  constructor(private readonly http: Http, private readonly token?: string) {}

  async collect(owner: string, repo: string, requestedRef?: string): Promise<RepositoryEvidence> {
    const base = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
    const headers = new Headers({ accept: "application/vnd.github+json", "x-github-api-version": "2026-03-10" });
    if (this.token) headers.set("authorization", `Bearer ${this.token}`);
    const metadata = await json<{ default_branch?: string }>(this.http, base, headers);
    const ref = requestedRef ?? metadata.default_branch;
    if (!ref) throw new Error("github_default_branch_missing");
    const commit = await json<{ sha?: string; commit?: { tree?: { sha?: string } } }>(this.http, `${base}/commits/${encodeURIComponent(ref)}`, headers);
    const resolvedCommitSha = commit.sha; const rootTreeSha = commit.commit?.tree?.sha;
    if (typeof resolvedCommitSha !== "string" || typeof rootTreeSha !== "string" || !/^[a-f0-9]{40}$/i.test(resolvedCommitSha) || !/^[a-f0-9]{40}$/i.test(rootTreeSha)) throw new Error("github_commit_identity_invalid");
    const immutableCommitSha = resolvedCommitSha;
    const immutableTreeSha = rootTreeSha;
    const response = await json<{ truncated?: boolean; tree?: TreeEntry[] }>(this.http, `${base}/git/trees/${immutableTreeSha}?recursive=1`, headers);
    const limitations: string[] = [];
    if (response.truncated) limitations.push("github_tree_truncated");
    const entries = (response.tree ?? []).filter((entry): entry is Required<TreeEntry> => typeof entry.path === "string" && entry.type === "blob" && typeof entry.sha === "string" && typeof entry.size === "number").sort((a, b) => a.path.localeCompare(b.path));
    if (entries.length > MAX_TREE_ENTRIES) limitations.push("tree_entry_limit_reached");
    const candidates = entries.slice(0, MAX_TREE_ENTRIES).filter(entry => category(entry.path) !== undefined);
    if (candidates.length > MAX_FILES) limitations.push("security_file_limit_reached");
    const securityFiles: RepositorySecurityFile[] = []; const inspected = new Map<string, string>(); let bytesInspected = 0;
    for (const entry of candidates.slice(0, MAX_FILES)) {
      const kind = category(entry.path)!;
      if (entry.size > MAX_FILE_BYTES || bytesInspected + entry.size > MAX_TOTAL_BYTES) { limitations.push(`security_file_oversized:${entry.path}`); securityFiles.push({ path: entry.path, category: kind, status: "oversized", findings: [] }); continue; }
      try {
        const data = await json<{ encoding?: string; content?: string }>(this.http, `${base}/contents/${encodeURIComponent(entry.path)}?ref=${immutableCommitSha}`, headers);
        if (data.encoding !== "base64" || typeof data.content !== "string") throw new Error("github_content_unsupported");
        const decoded = Buffer.from(data.content.replaceAll("\n", ""), "base64");
        if (decoded.byteLength > MAX_FILE_BYTES || bytesInspected + decoded.byteLength > MAX_TOTAL_BYTES) { limitations.push(`security_file_oversized:${entry.path}`); securityFiles.push({ path: entry.path, category: kind, status: "oversized", findings: [] }); continue; }
        if (decoded.includes(0)) { limitations.push(`security_file_binary:${entry.path}`); securityFiles.push({ path: entry.path, category: kind, status: "binary", findings: [] }); continue; }
        const text = new TextDecoder("utf-8", { fatal: true }).decode(decoded);
        bytesInspected += decoded.byteLength; inspected.set(entry.path, text); securityFiles.push({ path: entry.path, category: kind, status: "inspected", findings: inspect(entry.path, kind, text) });
      } catch (error) { limitations.push(`${error instanceof Error ? error.message : "github_content_error"}:${entry.path}`); securityFiles.push({ path: entry.path, category: kind, status: "unsupported", findings: [] }); }
    }
    const resolved = dependencies(inspected);
    const dependencyEvidence = { ...resolved, resolvedGraph: { packagesChecked: 0, nodesObserved: 0, errors: [] } };
    if (!securityFiles.some(file => file.category === "manifest" && file.status === "inspected")) limitations.push("dependency_resolution_unavailable");
    if (resolved.unresolved.length > 0) limitations.push("dependency_versions_unresolved");
    return { target: { repository: `github.com/${owner}/${repo}`, requestedRef: ref, resolvedCommitSha }, securityFiles, dependencies: dependencyEvidence, provenance: [], sourceErrors: [], coverage: { status: limitations.length === 0 ? "complete" : "partial", treeEntriesInspected: Math.min(entries.length, MAX_TREE_ENTRIES), filesInspected: securityFiles.filter(file => file.status === "inspected").length, bytesInspected, limitations: [...new Set(limitations)].sort() } };
  }
}
