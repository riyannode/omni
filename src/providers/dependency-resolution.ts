import { parse as parseToml } from "smol-toml";
import { parse as parseYaml } from "yaml";
import type { ExactDependencyCoordinate, RepositoryDependencyResolution, UnresolvedDependency } from "../domain/risk.ts";

const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const VERSION_WITH_PEERS = /^(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)(?:\([^)]*\))?$/;
const NPM_LOCK_NAMES = new Set(["package-lock.json", "npm-shrinkwrap.json", "bun.lock", "pnpm-lock.yaml", "yarn.lock"]);
const CARGO_LOCK_NAME = "cargo.lock";
const NPM_MANIFEST_NAME = "package.json";
const CARGO_MANIFEST_NAME = "cargo.toml";
const UNSUPPORTED_MANIFESTS: Record<string, string> = {
  "go.mod": "GO",
  "go.sum": "GO",
  "pyproject.toml": "PYPI"
};

type JsonRecord = Record<string, unknown>;
type DirectDependency = { name: string; requirement: string; local: boolean; workspace?: boolean; registryEligible?: boolean; packageName?: string };
type ParsedManifest = { path: string; ecosystem: "NPM" | "CARGO"; dependencies: DirectDependency[]; malformed: boolean; packageName?: string };
type Selection = { path?: string; reason?: "missing" | "ambiguous" };
type LockCache = Map<string, unknown | Error>;

export type DependencyResolutionInput = {
  files: ReadonlyMap<string, string>;
  candidatePaths: readonly string[];
  manifestDiscoveryComplete: boolean;
};

export type DependencyResolutionResult = {
  exact: ExactDependencyCoordinate[];
  unresolved: UnresolvedDependency[];
  limitations: string[];
  metadata: RepositoryDependencyResolution;
};

function record(value: unknown): JsonRecord | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as JsonRecord : undefined;
}

function stringValue(value: unknown): string | undefined { return typeof value === "string" ? value : undefined; }
function exactVersion(value: unknown): value is string { return typeof value === "string" && EXACT_VERSION.test(value); }
function exactVersionWithPeers(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const match = value.match(VERSION_WITH_PEERS);
  return match?.[1];
}
function normalizedPath(path: string): string { return path.replaceAll("\\", "/").replace(/^\.\//, ""); }
function directory(path: string): string { const slash = path.lastIndexOf("/"); return slash < 0 ? "." : path.slice(0, slash); }
function basename(path: string): string { return path.slice(path.lastIndexOf("/") + 1); }
function relativePath(root: string, path: string): string | undefined {
  const normalizedRoot = root === "." ? "" : `${root}/`;
  if (path === root) return ".";
  if (!path.startsWith(normalizedRoot)) return undefined;
  return path.slice(normalizedRoot.length) || ".";
}
function isAncestor(root: string, path: string): boolean { return relativePath(root, path) !== undefined; }
export function isDependencyResolutionPath(path: string): boolean {
  const name = basename(path).toLowerCase();
  return name === NPM_MANIFEST_NAME || name === CARGO_MANIFEST_NAME || NPM_LOCK_NAMES.has(name) || name === CARGO_LOCK_NAME || name === "pnpm-workspace.yaml" || name === "go.mod" || name === "go.sum" || name === "pyproject.toml" || /^requirements[^/]*\.txt$/.test(name);
}
function isManifestPath(path: string): boolean { return basename(path).toLowerCase() === NPM_MANIFEST_NAME || basename(path).toLowerCase() === CARGO_MANIFEST_NAME; }
function unsupportedEcosystemForPath(path: string): string | undefined {
  const name = basename(path).toLowerCase();
  return /^requirements[^/]*\.txt$/.test(name) ? "PYPI" : UNSUPPORTED_MANIFESTS[name];
}
function lockKind(path: string): "NPM" | "CARGO" | undefined {
  const name = basename(path).toLowerCase();
  if (NPM_LOCK_NAMES.has(name)) return "NPM";
  if (name === CARGO_LOCK_NAME) return "CARGO";
  return undefined;
}
function workspacePathFor(manifestPath: string): string { return directory(manifestPath); }
function sortUnique(values: readonly string[]): string[] { return [...new Set(values)].sort(); }

function localReference(requirement: string): boolean {
  return /^(?:workspace:|link:|file:|portal:)/i.test(requirement);
}

function unsupportedRegistryReference(requirement: string): boolean {
  return /^(?:npm:|git:|git\+|git@|github:|gitlab:|bitbucket:|https?:)/i.test(requirement) || /^(?!@)[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#.*)?$/.test(requirement);
}

function npmDependencies(value: string): { dependencies: DirectDependency[]; malformed: boolean } {
  try {
    const data = record(JSON.parse(value));
    if (!data) return { dependencies: [], malformed: true };
    const dependencies: DirectDependency[] = [];
    for (const group of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      const entries = record(data[group]);
      for (const [name, raw] of Object.entries(entries ?? {})) {
        const requirement = typeof raw === "string" ? raw : "<invalid>";
        dependencies.push({ name, requirement, local: typeof raw === "string" && localReference(raw), registryEligible: typeof raw === "string" ? !unsupportedRegistryReference(raw) : false });
      }
    }
    return { dependencies, malformed: false };
  } catch {
    return { dependencies: [], malformed: true };
  }
}

function cargoDependency(name: string, declaration: unknown): DirectDependency {
  if (typeof declaration === "string") return { name, requirement: declaration, local: localReference(declaration), registryEligible: true };
  const dependency = record(declaration);
  const requirement = stringValue(dependency?.version) ?? "<unspecified>";
  const packageName = stringValue(dependency?.package);
  const local = typeof dependency?.path === "string";
  const workspace = dependency?.workspace === true;
  const registryEligible = typeof dependency?.git !== "string" && (dependency?.registry === undefined || dependency?.registry === "crates-io");
  return { name, requirement, local, workspace, registryEligible, ...(packageName ? { packageName } : {}) };
}

function cargoDependencyEntries(value: unknown, output: DirectDependency[]): void {
  const table = record(value);
  if (!table) return;
  for (const [key, raw] of Object.entries(table)) {
    if (key === "dependencies" || key === "dev-dependencies" || key === "build-dependencies") {
      const group = record(raw);
      for (const [name, declaration] of Object.entries(group ?? {})) output.push(cargoDependency(name, declaration));
      continue;
    }
    if (key === "workspace") continue;
    if (key === "target") cargoDependencyEntries(raw, output);
    else if (record(raw)) cargoDependencyEntries(raw, output);
  }
}

function cargoWorkspaceDependency(value: string, name: string): DirectDependency | undefined {
  try {
    const data = record(parseToml(value) as unknown);
    const workspace = record(data?.workspace);
    const dependencies = record(workspace?.dependencies);
    const declaration = dependencies?.[name];
    return declaration === undefined ? undefined : cargoDependency(name, declaration);
  } catch { return undefined; }
}

function cargoDependencies(value: string): { dependencies: DirectDependency[]; malformed: boolean; packageName?: string } {
  try {
    const parsed = parseToml(value) as unknown;
    const data = record(parsed);
    if (!data) return { dependencies: [], malformed: true };
    const dependencies: DirectDependency[] = [];
    cargoDependencyEntries(data, dependencies);
    const seen = new Set<string>();
    const packageName = stringValue(record(data.package)?.name);
    return { dependencies: dependencies.filter(item => { const key = `${item.name}:${item.requirement}:${item.packageName ?? ""}:${item.local}`; if (seen.has(key)) return false; seen.add(key); return true; }), malformed: false, ...(packageName ? { packageName } : {}) };
  } catch {
    return { dependencies: [], malformed: true };
  }
}

function parseManifest(path: string, value: string): ParsedManifest {
  if (basename(path).toLowerCase() === NPM_MANIFEST_NAME) {
    const parsed = npmDependencies(value);
    return { path, ecosystem: "NPM", ...parsed };
  }
  const parsed = cargoDependencies(value);
  return { path, ecosystem: "CARGO", ...parsed };
}

function parseJsonRelaxed(value: string): unknown {
  try { return JSON.parse(value); } catch {
    let output = ""; let inString = false; let escaped = false;
    for (let index = 0; index < value.length; index += 1) {
      const character = value[index]!;
      if (inString) {
        output += character;
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') inString = false;
        continue;
      }
      if (character === '"') { inString = true; output += character; continue; }
      if (character === ",") {
        let next = index + 1;
        while (/\s/.test(value[next] ?? "")) next += 1;
        if (value[next] === "}" || value[next] === "]") continue;
      }
      output += character;
    }
    return JSON.parse(output);
  }
}

function packageNameAndVersion(locator: string): { name: string; version: string } | undefined {
  const separator = locator.startsWith("@") ? locator.indexOf("@", locator.indexOf("/") + 1) : locator.indexOf("@");
  if (separator <= 0) return undefined;
  const name = locator.slice(0, separator);
  const version = exactVersionWithPeers(locator.slice(separator + 1));
  return version ? { name, version } : undefined;
}

function workspacePatterns(rootPackage: JsonRecord | undefined): string[] {
  const workspaces = rootPackage?.workspaces;
  if (Array.isArray(workspaces)) return workspaces.filter((item): item is string => typeof item === "string");
  const object = record(workspaces);
  return Array.isArray(object?.packages) ? object.packages.filter((item): item is string => typeof item === "string") : [];
}

function workspacePatternMatches(pattern: string, path: string): boolean {
  const patternParts = normalizedPath(pattern).replace(/\/$/, "").split("/").filter(Boolean);
  const pathParts = normalizedPath(path).split("/").filter(Boolean);
  const match = (pi: number, xi: number): boolean => {
    if (pi === patternParts.length) return xi === pathParts.length;
    const part = patternParts[pi]!;
    if (part === "**") return match(pi + 1, xi) || (xi < pathParts.length && match(pi, xi + 1));
    if (xi >= pathParts.length) return false;
    if (part !== "*" && part !== pathParts[xi]) return false;
    return match(pi + 1, xi + 1);
  };
  return match(0, 0);
}

function packageWorkspaceOwns(root: string, manifestPath: string, files: ReadonlyMap<string, string>): boolean {
  const workspacePath = relativePath(root, directory(manifestPath));
  if (!workspacePath || workspacePath === ".") return true;
  const rootManifest = root === "." ? "package.json" : `${root}/package.json`;
  const value = files.get(rootManifest);
  if (!value) return false;
  try { return workspacePatterns(record(JSON.parse(value))).some(pattern => workspacePatternMatches(pattern, workspacePath)); } catch { return false; }
}

function cargoWorkspaceOwns(root: string, manifestPath: string, files: ReadonlyMap<string, string>): boolean {
  const workspacePath = relativePath(root, directory(manifestPath));
  if (!workspacePath || workspacePath === ".") return true;
  const rootManifest = root === "." ? "Cargo.toml" : `${root}/Cargo.toml`;
  const value = files.get(rootManifest);
  if (!value) return false;
  try {
    const data = record(parseToml(value) as unknown);
    const workspace = record(data?.workspace);
    const members = Array.isArray(workspace?.members) ? workspace.members.filter((item): item is string => typeof item === "string") : [];
    return members.some(member => workspacePatternMatches(member, workspacePath));
  } catch { return false; }
}

function bunWorkspaceOwns(lockValue: string, root: string, manifestPath: string): boolean {
  try {
    const parsed = record(parseJsonRelaxed(lockValue));
    const workspaces = record(parsed?.workspaces);
    const workspacePath = relativePath(root, directory(manifestPath));
    return workspacePath !== undefined && record(workspaces?.[workspacePath === "." ? "" : workspacePath]) !== undefined;
  } catch { return false; }
}

function pnpmImporterOwns(lockValue: string, root: string, manifestPath: string): boolean {
  try {
    const parsed = record(parseYaml(lockValue, { maxAliasCount: 1000 }));
    const importers = record(parsed?.importers);
    const workspacePath = relativePath(root, directory(manifestPath));
    return workspacePath !== undefined && record(importers?.[workspacePath === "." ? "." : workspacePath]) !== undefined;
  } catch { return false; }
}

function lockOwnsManifest(lockPath: string, manifestPath: string, files: ReadonlyMap<string, string>): boolean {
  const root = directory(lockPath);
  if (root === directory(manifestPath)) return true;
  const kind = lockKind(lockPath);
  const value = files.get(lockPath);
  if (!value) return false;
  if (kind === "CARGO") return cargoWorkspaceOwns(root, manifestPath, files);
  if (basename(lockPath).toLowerCase() === "bun.lock") return bunWorkspaceOwns(value, root, manifestPath) || packageWorkspaceOwns(root, manifestPath, files);
  if (basename(lockPath).toLowerCase() === "pnpm-lock.yaml") return pnpmImporterOwns(value, root, manifestPath) || packageWorkspaceOwns(root, manifestPath, files);
  return packageWorkspaceOwns(root, manifestPath, files);
}

function selectLock(manifest: ParsedManifest, candidatePaths: readonly string[], files: ReadonlyMap<string, string>): Selection {
  const manifestDir = directory(manifest.path);
  const candidates = candidatePaths.filter(path => lockKind(path) === manifest.ecosystem && isAncestor(directory(path), manifestDir)).sort((left, right) => {
    const leftDepth = directory(left) === "." ? 0 : directory(left).split("/").length;
    const rightDepth = directory(right) === "." ? 0 : directory(right).split("/").length;
    return rightDepth - leftDepth || left.localeCompare(right);
  });
  if (candidates.length === 0) return { reason: "missing" };
  const valid = candidates.filter(path => lockOwnsManifest(path, manifest.path, files));
  if (valid.length === 0) return { reason: "ambiguous" };
  const bestDepth = directory(valid[0]!) === "." ? 0 : directory(valid[0]!).split("/").length;
  const nearest = valid.filter(path => (directory(path) === "." ? 0 : directory(path).split("/").length) === bestDepth);
  const selected = nearest[0];
  return nearest.length === 1 && selected !== undefined ? { path: selected } : { reason: "ambiguous" };
}

function unresolved(item: DirectDependency, manifest: ParsedManifest, sourcePath?: string): UnresolvedDependency {
  return { ecosystem: manifest.ecosystem, name: item.packageName ?? item.name, requirement: item.requirement, ...(sourcePath ? { sourcePath } : {}), manifestPath: manifest.path, workspacePath: workspacePathFor(manifest.path) };
}

function exact(item: DirectDependency, manifest: ParsedManifest, version: string, sourcePath: string): ExactDependencyCoordinate {
  return { ecosystem: manifest.ecosystem, name: item.packageName ?? item.name, version, sourcePath, manifestPath: manifest.path, workspacePath: workspacePathFor(manifest.path) };
}

function npmDependencyRequirement(workspace: JsonRecord | undefined, name: string): string | undefined {
  for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const value = record(workspace?.[section])?.[name];
    if (typeof value === "string") return value;
  }
  return undefined;
}

function hasNpmDependencyMetadata(workspace: JsonRecord | undefined): boolean {
  return ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"].some(section => record(workspace?.[section]) !== undefined);
}

function npmPackageVersion(lock: JsonRecord, manifest: ParsedManifest, lockPath: string, item: DirectDependency): string | undefined {
  const lockfileVersion = typeof lock.lockfileVersion === "number" ? lock.lockfileVersion : undefined;
  const modernLock = lockfileVersion !== undefined && lockfileVersion >= 2;
  const legacyLock = lockfileVersion === 1;
  if (!modernLock && !legacyLock) return undefined;
  const packages = record(lock.packages);
  const lockRoot = directory(lockPath);
  const relativeWorkspace = relativePath(lockRoot, directory(manifest.path));
  if (!relativeWorkspace) return undefined;
  const workspaceKey = relativeWorkspace === "." ? "" : relativeWorkspace;
  const workspace = record(packages?.[workspaceKey]);
  const declaredRequirement = npmDependencyRequirement(workspace, item.name);
  if (declaredRequirement !== undefined && declaredRequirement !== item.requirement) return undefined;
  if (modernLock && (!workspace || !hasNpmDependencyMetadata(workspace) || declaredRequirement === undefined)) return undefined;
  if (!modernLock && workspaceKey !== "" && declaredRequirement === undefined) return undefined;
  const name = item.packageName ?? item.name;
  const packagePaths = [
    workspaceKey ? `${workspaceKey}/node_modules/${name}` : undefined,
    `node_modules/${name}`
  ].filter((path): path is string => path !== undefined);
  const versions = packagePaths.map(path => stringValue(record(packages?.[path])?.version)).filter(exactVersion);
  if (versions.length > 0) return [...new Set(versions)].length === 1 ? versions[0] : undefined;
  if (workspaceKey === "") {
    const dependencies = record(lock.dependencies);
    const version = stringValue(record(dependencies?.[name])?.version);
    if (exactVersion(version)) return version;
  }
  return undefined;
}

function resolveNpmLock(manifest: ParsedManifest, lockPath: string, lock: unknown, item: DirectDependency): string | undefined {
  const data = record(lock);
  if (!data) return undefined;
  return npmPackageVersion(data, manifest, lockPath, item);
}

function workspaceDependencyRequirement(workspace: JsonRecord | undefined, name: string): string | undefined {
  for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const value = record(workspace?.[section])?.[name];
    if (typeof value === "string") return value;
  }
  return undefined;
}

function bunPackageVersion(lock: JsonRecord, lockPath: string, manifest: ParsedManifest, item: DirectDependency): string | undefined {
  const workspaces = record(lock.workspaces);
  const relativeWorkspace = relativePath(directory(lockPath), directory(manifest.path));
  if (!relativeWorkspace) return undefined;
  const workspace = record(workspaces?.[relativeWorkspace === "." ? "" : relativeWorkspace]);
  if (!workspace) return undefined;
  if (workspace) {
    const declaredRequirement = workspaceDependencyRequirement(workspace, item.name);
    if (declaredRequirement !== item.requirement) return undefined;
  }
  const name = item.packageName ?? item.name;
  const packages = record(lock.packages) ?? lock;
  const entry = packages[name];
  const locators: string[] = [];
  if (Array.isArray(entry) && typeof entry[0] === "string") locators.push(entry[0]);
  for (const value of Object.values(packages ?? {})) if (Array.isArray(value) && typeof value[0] === "string") locators.push(value[0]);
  const versions = locators.map(packageNameAndVersion).filter((value): value is { name: string; version: string } => value?.name === name).map(value => value.version);
  return [...new Set(versions)].length === 1 ? versions[0] : undefined;
}

function pnpmPackageExists(data: JsonRecord, name: string, version: string): boolean {
  const keys = [...Object.keys(record(data.packages) ?? {}), ...Object.keys(record(data.snapshots) ?? {})];
  return keys.some(key => {
    const parsed = packageNameAndVersion(key.replace(/^\//, ""));
    return parsed?.name === name && parsed.version === version;
  });
}

function pnpmPackageVersion(lock: JsonRecord, lockPath: string, manifest: ParsedManifest, item: DirectDependency): string | undefined {
  const importers = record(lock.importers);
  const relativeWorkspace = relativePath(directory(lockPath), directory(manifest.path));
  if (!relativeWorkspace) return undefined;
  const importer = record(importers?.[relativeWorkspace === "." ? "." : relativeWorkspace]);
  if (!importer) return undefined;
  const versions: string[] = [];
  for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const entry = record(importer[section])?.[item.name];
    const raw = typeof entry === "string" ? entry : stringValue(record(entry)?.version);
    const specifier = stringValue(record(entry)?.specifier);
    if (specifier !== undefined && specifier !== item.requirement) continue;
    if (specifier === undefined) continue;
    const version = exactVersionWithPeers(raw);
    if (version && pnpmPackageExists(lock, item.packageName ?? item.name, version)) versions.push(version);
  }
  return [...new Set(versions)].length === 1 ? versions[0] : undefined;
}

function splitYarnSelectors(value: string): string[] {
  const selectors: string[] = []; let current = ""; let quote = false; let escaped = false;
  for (const character of value) {
    if (quote) {
      current += character;
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') quote = false;
    } else if (character === '"') { quote = true; current += character; }
    else if (character === ",") { if (current.trim()) selectors.push(current.trim()); current = ""; }
    else current += character;
  }
  if (current.trim()) selectors.push(current.trim());
  return selectors.map(item => item.replace(/^"|"$/g, ""));
}

function yarnEntries(value: string): Array<{ selectors: string[]; version: string }> | Error {
  const lines = value.split(/\r?\n/);
  if (!lines.some(line => /^#\s*yarn lockfile v1\s*$/.test(line.trim()))) return new Error("dependency_lock_unsupported:yarn.lock");
  const entries: Array<{ selectors: string[]; version: string }> = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    if (line.trim() === "" || line.trim().startsWith("#") || /^\s/.test(line) || !line.trimEnd().endsWith(":")) continue;
    const selectors = splitYarnSelectors(line.trimEnd().slice(0, -1));
    let version: string | undefined;
    for (index += 1; index < lines.length && /^\s/.test(lines[index]!); index += 1) {
      const match = lines[index]!.match(/^\s+version\s+["']([^"']+)["']\s*$/);
      if (match) version = match[1];
    }
    index -= 1;
    if (version) entries.push({ selectors, version });
  }
  return entries;
}

function yarnSelectorName(selector: string): { name: string; requirement: string; unsupported: boolean } | undefined {
  const separator = selector.startsWith("@") ? selector.indexOf("@", selector.indexOf("/") + 1) : selector.indexOf("@");
  if (separator <= 0) return undefined;
  const requirement = selector.slice(separator + 1);
  return { name: selector.slice(0, separator), requirement, unsupported: /^(?:npm:|workspace:|link:|file:)/i.test(requirement) };
}

function yarnPackageVersion(entries: Array<{ selectors: string[]; version: string }>, item: DirectDependency): string | undefined {
  const name = item.packageName ?? item.name;
  const versions = entries.flatMap(entry => entry.selectors.map(yarnSelectorName).filter((value): value is { name: string; requirement: string; unsupported: boolean } => value?.name === name && value.requirement === item.requirement && !value.unsupported).map(() => entry.version)).filter(exactVersion);
  return [...new Set(versions)].length === 1 ? versions[0] : undefined;
}

function cargoPackageVersion(lock: JsonRecord, manifest: ParsedManifest, item: DirectDependency): string | undefined {
  if (!manifest.packageName) return undefined;
  const packages = Array.isArray(lock.package) ? lock.package.map(value => record(value)).filter((value): value is JsonRecord => value !== undefined) : [];
  const owners = packages.filter(value => value.name === manifest.packageName);
  if (owners.length !== 1) return undefined;
  const targetName = item.packageName ?? item.name;
  const edges = Array.isArray(owners[0]!.dependencies) ? owners[0]!.dependencies.filter((value): value is string => typeof value === "string") : [];
  const matchingEdges = edges.map(edge => {
    const match = edge.match(/^([^ ]+)(?:\s+(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?))?/);
    return match && match[1] === targetName ? { version: match[2] } : undefined;
  }).filter((value): value is { version: string | undefined } => value !== undefined);
  if (matchingEdges.length === 0) return undefined;
  const candidates = packages.filter(value => value.name === targetName && typeof value.source === "string" && value.source.startsWith("registry+") && exactVersion(value.version));
  const versions = candidates.map(value => value.version).filter(exactVersion);
  const edgeVersions = new Set(matchingEdges.map(value => value.version).filter((value): value is string => value !== undefined));
  if (edgeVersions.size > 0) {
    const exact = versions.filter(value => edgeVersions.has(value));
    return exact.length === 1 ? exact[0] : undefined;
  }
  return [...new Set(versions)].length === 1 ? versions[0] : undefined;
}

function parseLock(path: string, value: string): unknown | Error {
  try {
    const name = basename(path).toLowerCase();
    if (name === "pnpm-lock.yaml") return parseYaml(value, { maxAliasCount: 1000 });
    if (name === "yarn.lock") return yarnEntries(value);
    if (name === "cargo.lock") return parseToml(value);
    if (name === "bun.lock") {
      try { return parseJsonRelaxed(value); }
      catch { return parseJsonRelaxed(`{${value}}`); }
    }
    return JSON.parse(value);
  } catch (error) {
    return error instanceof Error ? error : new Error("dependency_lock_malformed");
  }
}

function lockVersion(lockPath: string, manifest: ParsedManifest, lock: unknown | Error, item: DirectDependency): string | undefined {
  if (lock instanceof Error) return undefined;
  const name = item.packageName ?? item.name;
  const lockName = basename(lockPath).toLowerCase();
  if (lockName === "package-lock.json" || lockName === "npm-shrinkwrap.json") return resolveNpmLock(manifest, lockPath, lock, item);
  if (lockName === "bun.lock") return bunPackageVersion(record(lock) ?? {}, lockPath, manifest, item);
  if (lockName === "pnpm-lock.yaml") return pnpmPackageVersion(record(lock) ?? {}, lockPath, manifest, item);
  if (lockName === "yarn.lock") return Array.isArray(lock) ? yarnPackageVersion(lock as Array<{ selectors: string[]; version: string }>, item) : undefined;
  if (lockName === "cargo.lock") return cargoPackageVersion(record(lock) ?? {}, manifest, item);
  return undefined;
}

function lockMalformed(path: string, lock: unknown | Error): string | undefined {
  if (!(lock instanceof Error)) return undefined;
  if (basename(path).toLowerCase() === "yarn.lock" && lock.message.startsWith("dependency_lock_unsupported:")) return lock.message;
  return `dependency_lock_malformed:${path}`;
}

function addUnresolved(unresolvedDependencies: UnresolvedDependency[], item: DirectDependency, manifest: ParsedManifest, sourcePath?: string): void {
  unresolvedDependencies.push(unresolved(item, manifest, sourcePath));
}

const MAX_DEPENDENCY_LOCK_ENTRIES = 100_000;

function lockEntryCount(path: string, lock: unknown): number {
  const name = basename(path).toLowerCase();
  if (name === "cargo.lock") return Array.isArray(record(lock)?.package) ? (record(lock)!.package as unknown[]).length : 0;
  if (name === "yarn.lock") return Array.isArray(lock) ? lock.length : 0;
  const data = record(lock);
  if (!data) return 0;
  if (name === "pnpm-lock.yaml") return Object.keys(record(data.importers) ?? {}).length + Object.keys(record(data.packages) ?? {}).length + Object.keys(record(data.snapshots) ?? {}).length;
  if (name === "bun.lock") return Object.keys(record(data.packages) ?? data).length + Object.keys(record(data.workspaces) ?? {}).length;
  return Object.keys(record(data.packages) ?? {}).length + Object.keys(record(data.dependencies) ?? {}).length;
}

export function resolveRepositoryDependencies(input: DependencyResolutionInput): DependencyResolutionResult {
  const files = input.files;
  const candidatePaths = sortUnique(input.candidatePaths.map(normalizedPath));
  const manifests = candidatePaths.filter(isManifestPath).filter(path => files.has(path)).map(path => parseManifest(path, files.get(path)!)).sort((left, right) => left.path.localeCompare(right.path));
  const exactDependencies: ExactDependencyCoordinate[] = [];
  const unresolvedDependencies: UnresolvedDependency[] = [];
  const limitations: string[] = [];
  const resolversAttempted = new Set<string>();
  const unsupportedEcosystems = new Set<string>();
  let applicableExternalDependencyCount = 0;
  const lockCache: LockCache = new Map();

  for (const path of candidatePaths) {
    const ecosystem = unsupportedEcosystemForPath(path);
    if (ecosystem) unsupportedEcosystems.add(ecosystem);
  }

  for (const manifest of manifests) {
    const external = manifest.dependencies.filter(item => !item.local);
    for (const item of external.filter(item => item.registryEligible === false)) limitations.push(`dependency_specifier_unsupported:${manifest.path}:${item.name}`);
    if (manifest.malformed) {
      if (external.length === 0) {
        const unknown = { name: "<manifest>", requirement: "<malformed>", local: false };
        addUnresolved(unresolvedDependencies, unknown, manifest);
        applicableExternalDependencyCount += 1;
      } else for (const item of external) addUnresolved(unresolvedDependencies, item, manifest);
      limitations.push(`dependency_manifest_malformed:${manifest.path}`);
      resolversAttempted.add(manifest.ecosystem);
      continue;
    }
    if (external.length === 0) continue;
    resolversAttempted.add(manifest.ecosystem);
    const selection = selectLock(manifest, candidatePaths, files);
    if (!selection.path) {
      const limitation = selection.reason === "ambiguous" ? `dependency_lock_association_ambiguous:${manifest.path}` : `dependency_lock_missing:${manifest.path}`;
      limitations.push(limitation);
      applicableExternalDependencyCount += external.length;
      for (const item of external) addUnresolved(unresolvedDependencies, item, manifest);
      continue;
    }
    const lockPath = selection.path;
    const lockValue = files.get(lockPath);
    if (lockValue === undefined) {
      limitations.push(`dependency_lock_unavailable:${lockPath}`);
      applicableExternalDependencyCount += external.length;
      for (const item of external) addUnresolved(unresolvedDependencies, item, manifest, lockPath);
      continue;
    }
    let parsedLock = lockCache.get(lockPath);
    if (parsedLock === undefined) { parsedLock = parseLock(lockPath, lockValue); lockCache.set(lockPath, parsedLock); }
    const malformed = lockMalformed(lockPath, parsedLock);
    if (malformed) {
      limitations.push(malformed);
      applicableExternalDependencyCount += external.length;
      for (const item of external) addUnresolved(unresolvedDependencies, item, manifest, lockPath);
      continue;
    }
    if (lockEntryCount(lockPath, parsedLock) > MAX_DEPENDENCY_LOCK_ENTRIES) {
      limitations.push(`dependency_lock_entry_limit_reached:${lockPath}`);
      applicableExternalDependencyCount += external.length;
      for (const item of external) addUnresolved(unresolvedDependencies, item, manifest, lockPath);
      continue;
    }
    const effectiveExternal = external.map(item => {
      if (manifest.ecosystem !== "CARGO" || item.workspace !== true) return item;
      const rootManifest = `${directory(lockPath) === "." ? "" : `${directory(lockPath)}/`}Cargo.toml`;
      const inherited = cargoWorkspaceDependency(files.get(rootManifest) ?? "", item.name);
      if (!inherited) {
        limitations.push(`dependency_workspace_unresolved:${manifest.path}:${item.name}`);
        return { ...item, workspace: false, registryEligible: false, requirement: "<workspace>" };
      }
      return inherited;
    });
    for (const item of effectiveExternal) {
      if (item.local) continue;
      applicableExternalDependencyCount += 1;
      if (item.registryEligible === false) {
        addUnresolved(unresolvedDependencies, item, manifest, lockPath);
        limitations.push(`dependency_registry_unsupported:${manifest.path}:${item.packageName ?? item.name}`);
        continue;
      }
      const version = lockVersion(lockPath, manifest, parsedLock, item);
      if (version) exactDependencies.push(exact(item, manifest, version, lockPath));
      else {
        addUnresolved(unresolvedDependencies, item, manifest, lockPath);
        limitations.push(`dependency_version_unresolved:${manifest.path}:${item.packageName ?? item.name}`);
      }
    }
  }

  const metadata: RepositoryDependencyResolution = {
    manifestDiscoveryComplete: input.manifestDiscoveryComplete,
    supportedManifestCount: manifests.length,
    unsupportedEcosystems: sortUnique([...unsupportedEcosystems]),
    resolversAttempted: sortUnique([...resolversAttempted]),
    applicableExternalDependencyCount,
    unresolvedDependencyCount: unresolvedDependencies.length
  };
  limitations.push(...metadata.unsupportedEcosystems.map(ecosystem => `dependency_resolution_unsupported:${ecosystem}`));
  return {
    exact: exactDependencies.sort((left, right) => left.manifestPath.localeCompare(right.manifestPath) || left.workspacePath.localeCompare(right.workspacePath) || left.name.localeCompare(right.name) || left.version.localeCompare(right.version)),
    unresolved: unresolvedDependencies.sort((left, right) => left.manifestPath.localeCompare(right.manifestPath) || left.workspacePath.localeCompare(right.workspacePath) || left.name.localeCompare(right.name)),
    limitations: sortUnique(limitations),
    metadata
  };
}
