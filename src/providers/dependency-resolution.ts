import { parse as parseToml } from "smol-toml";
import { parse as parseYaml } from "yaml";
import { satisfies as satisfiesPep440, valid as validPep440, validRange as validPep440Range } from "@renovatebot/pep440";
import { createHash } from "node:crypto";
import type { DependencyEcosystem, ExactDependencyCoordinate, RepositoryDependencyResolution, UnresolvedDependency } from "../domain/risk.ts";

const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const VERSION_WITH_PEERS = /^(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)(?:\([^)]*\))?$/;
const NPM_LOCK_NAMES = new Set(["package-lock.json", "npm-shrinkwrap.json", "bun.lock", "pnpm-lock.yaml", "yarn.lock"]);
const CARGO_LOCK_NAME = "cargo.lock";
const PYPI_LOCK_NAMES = new Set(["uv.lock", "poetry.lock"]);
const NPM_MANIFEST_NAME = "package.json";
const CARGO_MANIFEST_NAME = "cargo.toml";
const PYPROJECT_MANIFEST_NAME = "pyproject.toml";
const GO_MANIFEST_NAME = "go.mod";
const GO_VENDOR_MANIFEST = /(^|\/)vendor\/modules\.txt$/i;

type JsonRecord = Record<string, unknown>;
type DirectDependency = { name: string; requirement: string; local: boolean; workspace?: boolean; registryEligible?: boolean; packageName?: string; specifier?: string; exactVersion?: string };
type ParsedManifest = { path: string; ecosystem: DependencyEcosystem; dependencies: DirectDependency[]; malformed: boolean; packageName?: string; poetryContentHash?: string };
type Selection = { path?: string; reason?: "missing" | "ambiguous" };
type LockCache = Map<string, unknown | Error>;
type GoReplacement = { oldName: string; oldVersion?: string; local: boolean; name?: string; version?: string };
type GoExclude = { name: string; version: string };
type GoParsedDependencies = { requires: DirectDependency[]; replacements: GoReplacement[]; excludes: GoExclude[]; malformed: boolean };
type GoVendorModule = { name: string; version?: string; explicit: boolean; hasPackage: boolean; replacementName?: string; replacementVersion?: string; localReplacement?: string };

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
  return name === NPM_MANIFEST_NAME || name === CARGO_MANIFEST_NAME || NPM_LOCK_NAMES.has(name) || PYPI_LOCK_NAMES.has(name) || name === CARGO_LOCK_NAME || name === "pnpm-workspace.yaml" || name === GO_MANIFEST_NAME || name === "go.sum" || name === PYPROJECT_MANIFEST_NAME || GO_VENDOR_MANIFEST.test(path) || /^requirements[^/]*\.txt$/.test(name);
}
function isManifestPath(path: string): boolean {
  const name = basename(path).toLowerCase();
  return name === NPM_MANIFEST_NAME || name === CARGO_MANIFEST_NAME || name === GO_MANIFEST_NAME || name === PYPROJECT_MANIFEST_NAME || /^requirements[^/]*\.txt$/.test(name);
}
function isRequirementsPath(path: string): boolean { return /^requirements[^/]*\.txt$/.test(basename(path).toLowerCase()); }
function lockKind(path: string): DependencyEcosystem | undefined {
  const name = basename(path).toLowerCase();
  if (NPM_LOCK_NAMES.has(name)) return "NPM";
  if (PYPI_LOCK_NAMES.has(name)) return "PYPI";
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

function normalizePythonPackageName(name: string): string { return name.trim().toLowerCase().replace(/[._-]+/g, "-"); }
function validPythonVersion(value: string): boolean { return validPep440(value) !== null; }
function validPythonSpecifier(value: string): boolean { return value.length > 0 && validPep440Range(value); }
function pythonLocalReference(value: string): boolean { return /^(?:file:|\.{0,2}\/|\/|~\/|[A-Za-z]:[\\/])/u.test(value.trim()); }
function pythonRemoteReference(value: string): boolean { return /^(?:git\+|git:|git@|github:|https?:)/i.test(value.trim()) || /\s+@\s+(?:https?|git\+):/i.test(value); }
function isPublicPyPIIndex(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname.toLowerCase() === "pypi.org" && url.port === "" && url.username === "" && url.password === "" && url.search === "" && url.hash === "" && url.pathname.replace(/\/+$/u, "") === "/simple";
  } catch { return false; }
}
function pythonJsonStringify(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value).replace(/[\u0080-\uffff]/g, character => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
  if (typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(pythonJsonStringify).join(", ")}]`;
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map(key => `${pythonJsonStringify(key)}: ${pythonJsonStringify(object[key])}`).join(", ")}}`;
  }
  return "null";
}
function poetryContentHash(data: JsonRecord, withDependencyGroups = true): string {
  const project = record(data.project) ?? {};
  const group = withDependencyGroups ? data["dependency-groups"] : undefined;
  const poetry = record(record(data.tool)?.poetry) ?? {};
  const relevantProject: JsonRecord = {};
  for (const key of ["requires-python", "dependencies", "optional-dependencies"]) if (project[key] !== undefined) relevantProject[key] = project[key];
  const legacyKeys = ["dependencies", "source", "extras", "dev-dependencies"];
  const relevantPoetry: JsonRecord = {};
  const hasProject = Object.keys(relevantProject).length > 0;
  const hasGroups = record(group) !== undefined && Object.keys(record(group)!).length > 0;
  for (const key of [...legacyKeys, "group"]) {
    const value = poetry[key];
    if (value === undefined && (!legacyKeys.includes(key) || hasProject || hasGroups)) continue;
    relevantPoetry[key] = value ?? null;
  }
  const relevant: JsonRecord = {};
  if (hasProject) relevant.project = relevantProject;
  if (hasGroups) relevant["dependency-groups"] = group;
  if (Object.keys(relevant).length > 0) relevant.tool = { poetry: relevantPoetry };
  else return createHash("sha256").update(pythonJsonStringify(relevantPoetry)).digest("hex");
  return createHash("sha256").update(pythonJsonStringify(relevant)).digest("hex");
}
function poetryPublicPyPIConfigured(poetry: JsonRecord | undefined): boolean {
  const sources = poetry?.source;
  if (!Array.isArray(sources)) return true;
  let primaryCustom = false;
  let explicitPyPI = false;
  for (const value of sources) {
    const source = record(value);
    const name = stringValue(source?.name)?.toLowerCase();
    if (!name) return false;
    if (name === "pypi") {
      if (source?.url !== undefined) return false;
      explicitPyPI = true;
      continue;
    }
    const priority = stringValue(source?.priority)?.toLowerCase() ?? "primary";
    if (priority !== "supplemental" && priority !== "explicit") primaryCustom = true;
  }
  return !primaryCustom || explicitPyPI;
}
function pythonRequirementName(value: string): string | undefined {
  return value.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/)?.[1];
}

function poetrySpecifier(value: string): string | undefined {
  const raw = value.trim();
  if (!raw || raw === "*") return undefined;
  if (/^\^\s*\d/.test(raw)) {
    const version = raw.slice(1).trim();
    if (!/^\d+(?:\.\d+){0,2}$/u.test(version)) return undefined;
    const parts = version.split(".").map(Number);
    if (parts.length < 1 || parts.some(part => !Number.isSafeInteger(part) || part < 0)) return undefined;
    const [major = 0, minor = 0, patch = 0] = parts;
    const upper = major > 0 ? `${major + 1}.0.0` : minor > 0 ? `0.${minor + 1}.0` : `0.0.${patch + 1}`;
    return `>=${version},<${upper}`;
  }
  if (/^~\s*\d/.test(raw)) {
    const version = raw.slice(1).trim();
    if (!/^\d+(?:\.\d+){0,2}$/u.test(version)) return undefined;
    const parts = version.split(".").map(Number);
    if (parts.length < 1 || parts.some(part => !Number.isSafeInteger(part) || part < 0)) return undefined;
    const [major, minor = 0] = parts;
    return `>=${version},<${major}.${minor + 1}`;
  }
  const normalized = /^\d/.test(raw) ? `==${raw}` : raw;
  return validPythonSpecifier(normalized) ? normalized : undefined;
}

function pythonDependencyFromRequirement(value: string, poetry = false): DirectDependency | undefined {
  const requirement = value.trim();
  if (!requirement || requirement.startsWith("#") || /^(?:--?(?:requirement|constraint)\b|-r\b|-c\b|--(?:index-url|extra-index-url|trusted-host|no-index|require-hashes)\b)/i.test(requirement)) return undefined;
  if (/^-{1,2}e(?:ditable)?\s+/i.test(requirement)) {
    const target = requirement.replace(/^-{1,2}e(?:ditable)?\s+/i, "").trim();
    const egg = target.match(/[#&]egg=([^&\s]+)/i)?.[1];
    const name = egg ? normalizePythonPackageName(egg) : "<editable>";
    return { name, requirement, local: pythonLocalReference(target), registryEligible: false };
  }
  const markerIndex = requirement.indexOf(";");
  const base = (markerIndex >= 0 ? requirement.slice(0, markerIndex) : requirement).trim();
  const hasEnvironmentMarker = markerIndex >= 0 && requirement.slice(markerIndex + 1).trim().length > 0;
  const direct = base.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*@\s*(\S+)$/);
  const shorthand = /^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9_.-]+(?:#.*)?$/u.test(base);
  if (!direct && (pythonRemoteReference(base) || shorthand)) return { name: base, requirement, local: false, registryEligible: false };
  const packagePrefix = base.match(/^([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]+\])?)/u);
  const name = direct?.[1] ?? packagePrefix?.[1]?.replace(/\[[^\]]+\]$/u, "") ?? pythonRequirementName(base);
  if (!name) {
    if (pythonRemoteReference(base)) return { name: base, requirement, local: false, registryEligible: false };
    return undefined;
  }
  const canonicalName = normalizePythonPackageName(name);
  const target = direct?.[2] ?? base.slice(direct ? base.indexOf(direct[2]!) : packagePrefix?.[1]?.length ?? name.length).trim();
  const local = pythonLocalReference(target);
  const remote = pythonRemoteReference(target);
  const specifier = poetry ? poetrySpecifier(target) : target || undefined;
  const exact = !poetry && target.match(/^==\s*([^\s]+)$/)?.[1];
  const exactVersion = exact && !exact.includes("*") && validPythonVersion(exact) ? exact : undefined;
  return {
    name: canonicalName,
    requirement,
    local,
    registryEligible: !local && !remote && !hasEnvironmentMarker,
    ...(specifier ? { specifier } : {}),
    ...(exactVersion ? { exactVersion } : {})
  };
}

function requirementsDependencies(value: string): { dependencies: DirectDependency[]; malformed: boolean } {
  const dependencies: DirectDependency[] = [];
  const lines = value.split(/\r?\n/u);
  let sourceAmbiguous = false;
  for (const rawLine of lines) {
    const line = rawLine.replace(/\s+#.*$/u, "").trim();
    const sourceDirective = line.match(/^--(index-url|extra-index-url|find-links)(?:=|\s+)(\S+)$/i);
    if (sourceDirective && (sourceDirective[1]!.toLowerCase() !== "index-url" || !isPublicPyPIIndex(sourceDirective[2]!))) sourceAmbiguous = true;
    if (!sourceDirective && /^--(?:index-url|extra-index-url|find-links)(?:\s|=|$)/i.test(line)) sourceAmbiguous = true;
    if (/^--no-index(?:\s|=|$)/i.test(line)) sourceAmbiguous = true;
  }
  for (const rawLine of lines) {
    const line = rawLine.replace(/\s+#.*$/u, "").trim();
    if (!line || line.startsWith("#") || /^--hash(?:=|\s)/i.test(line)) continue;
    const sourceDirective = line.match(/^--(index-url|extra-index-url|find-links)(?:=|\s+)(\S+)$/i);
    if (sourceDirective) {
      if (sourceDirective[1]!.toLowerCase() !== "index-url" || !isPublicPyPIIndex(sourceDirective[2]!)) sourceAmbiguous = true;
      continue;
    }
    if (/^--no-index(?:\s|=|$)/i.test(line)) { sourceAmbiguous = true; continue; }
    if (/^(?:-r|--requirement|-c|--constraint)\b/i.test(line)) continue;
    const withoutHashes = line.replace(/\s+--hash(?:=|\s+)\S+/gi, "").trim();
    const dependency = pythonDependencyFromRequirement(withoutHashes);
    if (dependency) dependencies.push(sourceAmbiguous && !dependency.local ? { ...dependency, registryEligible: false } : dependency);
  }
  return { dependencies, malformed: false };
}

function pythonDependencyFromPoetry(name: string, value: unknown): DirectDependency | undefined {
  if (name.toLowerCase() === "python") return undefined;
  const declaration = record(value);
  if (typeof value === "string") return pythonDependencyFromRequirement(`${name} ${value}`, true);
  if (!declaration) return { name: normalizePythonPackageName(name), requirement: "<invalid>", local: false, registryEligible: false };
  const rawVersion = stringValue(declaration.version) ?? "<unspecified>";
  const local = typeof declaration.path === "string";
  const remote = typeof declaration.git === "string" || typeof declaration.url === "string" || (typeof declaration.source === "string" && declaration.source.toLowerCase() !== "pypi");
  const specifier = rawVersion === "<unspecified>" ? undefined : poetrySpecifier(rawVersion);
  return { name: normalizePythonPackageName(name), requirement: rawVersion, local, registryEligible: !local && !remote, ...(specifier ? { specifier } : {}) };
}

function pyprojectDependencies(value: string): { dependencies: DirectDependency[]; malformed: boolean; packageName?: string } {
  try {
    const data = record(parseToml(value) as unknown);
    if (!data) return { dependencies: [], malformed: true };
    const dependencies: DirectDependency[] = [];
    const project = record(data.project);
    const projectName = stringValue(project?.name);
    const projectDependencies = project?.dependencies;
    if (Array.isArray(projectDependencies)) for (const item of projectDependencies) if (typeof item === "string") {
      const dependency = pythonDependencyFromRequirement(item);
      if (dependency) dependencies.push(dependency);
    }
    const optional = record(project?.["optional-dependencies"]);
    for (const values of Object.values(optional ?? {})) if (Array.isArray(values)) for (const item of values) if (typeof item === "string") {
      const dependency = pythonDependencyFromRequirement(item);
      if (dependency) dependencies.push(dependency);
    }
    const tool = record(data.tool);
    const poetry = record(tool?.poetry);
    for (const [name, declaration] of Object.entries(record(poetry?.dependencies) ?? {})) {
      const dependency = pythonDependencyFromPoetry(name, declaration);
      if (dependency) dependencies.push(dependency);
    }
    for (const group of Object.values(record(poetry?.group) ?? {})) for (const [name, declaration] of Object.entries(record(record(group)?.dependencies) ?? {})) {
      const dependency = pythonDependencyFromPoetry(name, declaration);
      if (dependency) dependencies.push(dependency);
    }
    const uvSources = record(record(tool?.uv)?.sources);
    const poetryPublicPyPI = poetryPublicPyPIConfigured(poetry);
    const adjusted = dependencies.map(item => {
      const sourceEntry = Object.entries(uvSources ?? {}).find(([name]) => normalizePythonPackageName(name) === item.name);
      const source = record(sourceEntry?.[1]);
      if (!source) return poetryPublicPyPI ? item : { ...item, registryEligible: false };
      const local = typeof source.path === "string" || typeof source.workspace === "string" || typeof source.editable === "string";
      const remote = typeof source.git === "string" || typeof source.url === "string" || typeof source.index === "string";
      return { ...item, local: item.local || local, registryEligible: item.registryEligible !== false && !local && !remote && poetryPublicPyPI };
    });
    const seen = new Set<string>();
    return { dependencies: adjusted.filter(item => { const key = `${item.name}:${item.requirement}:${item.local}:${item.registryEligible}`; if (seen.has(key)) return false; seen.add(key); return true; }), malformed: false, ...(projectName ? { packageName: normalizePythonPackageName(projectName) } : poetry?.name && typeof poetry.name === "string" ? { packageName: normalizePythonPackageName(poetry.name) } : {}), ...(poetry ? { poetryContentHash: poetryContentHash(data) } : {}) };
  } catch {
    return { dependencies: [], malformed: true };
  }
}

const GO_VERSION = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

type ParsedGoVersion = { major: number; minor: number; patch: number; prerelease: string[] };

function parseGoVersion(value: string): ParsedGoVersion | undefined {
  const match = value.match(GO_VERSION);
  if (!match) return undefined;
  const numbers = [Number(match[1]), Number(match[2]), Number(match[3])];
  if (numbers.some(number => !Number.isSafeInteger(number))) return undefined;
  return { major: numbers[0]!, minor: numbers[1]!, patch: numbers[2]!, prerelease: match[4]?.split(".") ?? [] };
}

function validGoModuleVersion(value: string): boolean { return parseGoVersion(value) !== undefined; }
function goLocalReference(value: string): boolean { return /^(?:\.{0,2}\/|\/|[A-Za-z]:[\\/])/u.test(value); }

function parseGoRequireLine(line: string): DirectDependency | undefined {
  const fields = line.trim().split(/\s+/u);
  if (fields.length !== 2 || !fields[0] || !validGoModuleVersion(fields[1]!)) return undefined;
  return { name: fields[0], requirement: fields[1]!, local: false, registryEligible: true };
}

function parseGoExcludeLine(line: string): GoExclude | undefined {
  const fields = line.trim().split(/\s+/u);
  if (fields.length !== 2 || !fields[0] || !validGoModuleVersion(fields[1]!)) return undefined;
  return { name: fields[0]!, version: fields[1]! };
}

function parseGoReplacementLine(line: string): GoReplacement | undefined {
  const parts = line.split("=>");
  if (parts.length !== 2) return undefined;
  const left = parts[0]!.trim().split(/\s+/u);
  const right = parts[1]!.trim().split(/\s+/u);
  if ((left.length !== 1 && left.length !== 2) || (right.length !== 1 && right.length !== 2) || !left[0] || !right[0]) return undefined;
  const oldVersion = left[1];
  if (oldVersion !== undefined && !validGoModuleVersion(oldVersion)) return undefined;
  if (goLocalReference(right[0]!)) return { oldName: left[0]!, ...(oldVersion ? { oldVersion } : {}), local: true };
  if (right.length !== 2 || !validGoModuleVersion(right[1]!)) return undefined;
  return { oldName: left[0]!, ...(oldVersion ? { oldVersion } : {}), local: false, name: right[0]!, version: right[1]! };
}

function parseGoDependencies(value: string): GoParsedDependencies {
  const requires: DirectDependency[] = [];
  const replacements: GoReplacement[] = [];
  const excludes: GoExclude[] = [];
  let section: "require" | "replace" | "exclude" | undefined;
  let malformed = false;
  for (const rawLine of value.split(/\r?\n/u)) {
    const line = rawLine.replace(/\s+\/\/.*$/u, "").trim();
    if (!line) continue;
    const start = line.match(/^(require|replace|exclude)\s*\($/u);
    if (start) { section = start[1] as "require" | "replace" | "exclude"; continue; }
    if (line === ")") { if (!section) malformed = true; section = undefined; continue; }
    const standalone = line.match(/^(require|replace|exclude)\s+(.+)$/u);
    if (standalone && !section) {
      const item = standalone[1] === "require" ? parseGoRequireLine(standalone[2]!) : standalone[1] === "replace" ? parseGoReplacementLine(standalone[2]!) : parseGoExcludeLine(standalone[2]!);
      if (!item) malformed = true;
      else if (standalone[1] === "require") requires.push(item as DirectDependency);
      else if (standalone[1] === "replace") replacements.push(item as GoReplacement);
      else excludes.push(item as GoExclude);
      continue;
    }
    const item = section === "require" ? parseGoRequireLine(line) : section === "replace" ? parseGoReplacementLine(line) : section === "exclude" ? parseGoExcludeLine(line) : undefined;
    if (section && !item) malformed = true;
    else if (section === "require") requires.push(item as DirectDependency);
    else if (section === "replace") replacements.push(item as GoReplacement);
    else if (section === "exclude") excludes.push(item as GoExclude);
  }
  if (section !== undefined) malformed = true;
  return { requires, replacements, excludes, malformed };
}

function goDependencies(value: string): { dependencies: DirectDependency[]; malformed: boolean } {
  const parsed = parseGoDependencies(value);
  const dependencies = parsed.requires.map(item => {
    const matching = parsed.replacements.filter(candidate => candidate.oldName === item.name && (candidate.oldVersion === undefined || candidate.oldVersion === item.requirement));
    if (matching.length === 0) return item;
    if (matching.length > 1) return { ...item, registryEligible: false };
    const replacement = matching[0]!;
    if (replacement.local) return { ...item, local: true, registryEligible: false };
    return { ...item, name: replacement.name!, packageName: replacement.name!, requirement: replacement.version!, specifier: replacement.version! };
  });
  return { dependencies, malformed: parsed.malformed };
}

function parseGoVendorModules(value: string): Map<string, GoVendorModule[]> | Error {
  const modules = new Map<string, GoVendorModule[]>();
  let current: GoVendorModule | undefined;
  for (const rawLine of value.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith("## ")) {
      if (current && line.slice(3).split(";").map(item => item.trim()).includes("explicit")) current.explicit = true;
      continue;
    }
    if (line.startsWith("# ")) {
      const body = line.slice(1).trim();
      const match = body.match(/^(\S+)(?:\s+(v\S+))?(?:\s+=>\s+(\S+)(?:\s+(v\S+))?)?$/u);
      if (!match || (match[2] !== undefined && !validGoModuleVersion(match[2])) || (match[4] !== undefined && !validGoModuleVersion(match[4]))) return new Error("dependency_vendor_malformed");
      if (!match[2] && !match[3]) { current = undefined; continue; }
      const module: GoVendorModule = { name: match[1]!, explicit: false, hasPackage: false };
      if (match[2]) module.version = match[2];
      if (match[3]) {
        if (goLocalReference(match[3])) module.localReplacement = match[3];
        else {
          if (!match[4]) return new Error("dependency_vendor_malformed");
          module.replacementName = match[3]; module.replacementVersion = match[4];
        }
      }
      current = module;
      modules.set(module.name, [...(modules.get(module.name) ?? []), module]);
      continue;
    }
    if (line.startsWith("#")) return new Error("dependency_vendor_malformed");
    if (current) {
      if (line.split(/\s+/u).length !== 1) return new Error("dependency_vendor_malformed");
      current.hasPackage = true;
    }
  }
  return modules;
}

function goVendorPathForManifest(manifestPath: string, candidatePaths: readonly string[]): string | undefined {
  const manifestDirectory = directory(manifestPath);
  const candidates = candidatePaths.filter(path => GO_VENDOR_MANIFEST.test(path) && directory(directory(path)) === manifestDirectory).sort();
  return candidates.length === 1 ? candidates[0] : undefined;
}

function goVendorConsistent(parsed: GoParsedDependencies, vendor: Map<string, GoVendorModule[]>): boolean {
  const directRecords = new Set<GoVendorModule>();
  for (const item of parsed.requires) {
    const replacements = parsed.replacements.filter(candidate => candidate.oldName === item.name && (candidate.oldVersion === undefined || candidate.oldVersion === item.requirement));
    if (replacements.length > 1) return false;
    const records = (vendor.get(item.name) ?? []).filter(record => record.version === item.requirement);
    if (records.length !== 1) continue;
    const record = records[0]!;
    directRecords.add(record);
    const replacement = replacements[0];
    if (!replacement) {
      if (record.replacementName !== undefined || record.localReplacement !== undefined) return false;
      continue;
    }
    if (replacement.local) {
      if (record.localReplacement === undefined || record.replacementName !== undefined) return false;
    } else if (record.replacementName !== replacement.name || record.replacementVersion !== replacement.version || record.localReplacement !== undefined) return false;
  }
  for (const replacement of parsed.replacements) {
    const records = (vendor.get(replacement.oldName) ?? []).filter(record => replacement.oldVersion === undefined || record.version === replacement.oldVersion);
    if (records.length !== 1) return false;
    const record = records[0]!;
    if (!directRecords.has(record)) return false;
    if (replacement.local ? record.localReplacement === undefined : record.replacementName !== replacement.name || record.replacementVersion !== replacement.version) return false;
  }
  for (const exclude of parsed.excludes) {
    const records = vendor.get(exclude.name) ?? [];
    if (records.some(record => record.version === exclude.version && directRecords.has(record))) return false;
  }
  for (const records of vendor.values()) for (const record of records) {
    if (record.explicit && !directRecords.has(record)) return false;
  }
  return true;
}

function goVendorDependency(item: DirectDependency, parsed: GoParsedDependencies, vendor: Map<string, GoVendorModule[]>): DirectDependency {
  const replacements = parsed.replacements.filter(candidate => candidate.oldName === item.name && (candidate.oldVersion === undefined || candidate.oldVersion === item.requirement));
  if (replacements.length > 1) return { ...item, registryEligible: false };
  const replacement = replacements[0];
  const records = (vendor.get(item.name) ?? []).filter(record => record.version === item.requirement);
  if (records.length !== 1) return { ...item, registryEligible: false };
  const record = records[0]!;
  if (!record.explicit || !record.hasPackage) return { ...item, registryEligible: false };
  if (replacement?.local) return { ...item, local: record.localReplacement !== undefined, registryEligible: false };
  if (replacement && !replacement.local) {
    if (record.replacementName !== replacement.name || record.replacementVersion !== replacement.version) return { ...item, registryEligible: false };
    if (parsed.excludes.some(exclude => exclude.name === replacement.name && exclude.version === replacement.version)) return { ...item, registryEligible: false };
    return { ...item, name: replacement.name!, packageName: replacement.name!, requirement: replacement.version!, specifier: replacement.version! };
  }
  if (!record.version || record.version !== item.requirement) return { ...item, registryEligible: false };
  if (parsed.excludes.some(exclude => exclude.name === item.name && exclude.version === record.version)) return { ...item, registryEligible: false };
  return { ...item, name: record.name, packageName: record.name, requirement: record.version, specifier: record.version };
}

function pythonPackageRecords(lock: unknown): JsonRecord[] {
  const packages = record(lock)?.package;
  return Array.isArray(packages) ? packages.map(record).filter((item): item is JsonRecord => item !== undefined) : [];
}

function pythonLockVersionMatches(item: DirectDependency, version: string): boolean {
  return item.specifier !== undefined && validPythonSpecifier(item.specifier) && validPythonVersion(version) && satisfiesPep440(version, item.specifier);
}

function normalizePath(value: string): string { return value.replaceAll("\\", "/").replace(/^\.\//u, "").replace(/\/$/u, "") || "."; }

function uvRootPackage(lock: JsonRecord, lockPath: string, manifest: ParsedManifest): JsonRecord | undefined {
  if (!manifest.packageName) return undefined;
  const root = relativePath(directory(lockPath), directory(manifest.path));
  if (root === undefined) return undefined;
  const candidates = pythonPackageRecords(lock).filter(item => {
    const editable = stringValue(record(item.source)?.editable);
    return normalizePythonPackageName(stringValue(item.name) ?? "") === manifest.packageName && editable !== undefined && normalizePath(editable) === normalizePath(root);
  });
  return candidates.length === 1 ? candidates[0] : undefined;
}

function uvPackageVersion(lock: JsonRecord, lockPath: string, manifest: ParsedManifest, item: DirectDependency): string | undefined {
  const root = uvRootPackage(lock, lockPath, manifest);
  if (!root) return undefined;
  const direct = Array.isArray(root.dependencies) ? root.dependencies.filter(value => normalizePythonPackageName(stringValue(record(value)?.name) ?? "") === item.name) : [];
  if (direct.length !== 1) return undefined;
  const requiresDist = Array.isArray(record(root.metadata)?.["requires-dist"]) ? record(root.metadata)!["requires-dist"] as unknown[] : [];
  const metadataMatches = requiresDist.filter(value => normalizePythonPackageName(stringValue(record(value)?.name) ?? "") === item.name);
  if (metadataMatches.length > 1) return undefined;
  if (metadataMatches.length === 1 && stringValue(record(metadataMatches[0])?.specifier) !== item.specifier) return undefined;
  const versions = pythonPackageRecords(lock).filter(candidate => normalizePythonPackageName(stringValue(candidate.name) ?? "") === item.name && isPublicPyPIIndex(stringValue(record(candidate.source)?.registry) ?? "") && exactPythonVersion(stringValue(candidate.version))).map(candidate => stringValue(candidate.version)!);
  const unique = [...new Set(versions)];
  return unique.length === 1 && pythonLockVersionMatches(item, unique[0]!) ? unique[0] : undefined;
}

function exactPythonVersion(value: string | undefined): value is string { return value !== undefined && validPythonVersion(value); }

function poetryPackageVersion(lock: JsonRecord, manifest: ParsedManifest, item: DirectDependency): string | undefined {
  const metadata = record(lock.metadata);
  const lockVersion = stringValue(metadata?.["lock-version"]);
  const contentHash = stringValue(metadata?.["content-hash"]);
  if ((lockVersion !== "2.0" && lockVersion !== "2.1") || !contentHash || !/^[a-f0-9]{64}$/u.test(contentHash) || manifest.poetryContentHash !== contentHash) return undefined;
  const versions = pythonPackageRecords(lock).filter(candidate => normalizePythonPackageName(stringValue(candidate.name) ?? "") === item.name && candidate.source === undefined && exactPythonVersion(stringValue(candidate.version))).map(candidate => stringValue(candidate.version)!);
  const unique = [...new Set(versions)];
  return unique.length === 1 && pythonLockVersionMatches(item, unique[0]!) ? unique[0] : undefined;
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
  const name = basename(path).toLowerCase();
  if (name === NPM_MANIFEST_NAME) {
    const parsed = npmDependencies(value);
    return { path, ecosystem: "NPM", ...parsed };
  }
  if (name === CARGO_MANIFEST_NAME) {
    const parsed = cargoDependencies(value);
    return { path, ecosystem: "CARGO", ...parsed };
  }
  if (name === GO_MANIFEST_NAME) return { path, ecosystem: "GO", ...goDependencies(value) };
  if (name === PYPROJECT_MANIFEST_NAME) return { path, ecosystem: "PYPI", ...pyprojectDependencies(value) };
  return { path, ecosystem: "PYPI", ...requirementsDependencies(value) };
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

function pythonWorkspaceOwns(root: string, manifestPath: string, files: ReadonlyMap<string, string>): boolean {
  const workspacePath = relativePath(root, directory(manifestPath));
  if (!workspacePath || workspacePath === ".") return true;
  const rootManifest = root === "." ? PYPROJECT_MANIFEST_NAME : `${root}/${PYPROJECT_MANIFEST_NAME}`;
  const value = files.get(rootManifest);
  if (!value) return false;
  try {
    const data = record(parseToml(value) as unknown);
    const workspace = record(record(data?.tool)?.uv)?.workspace;
    const members = Array.isArray(record(workspace)?.members) ? record(workspace)!.members as unknown[] : [];
    return members.filter((item): item is string => typeof item === "string").some(member => workspacePatternMatches(member, workspacePath));
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
  if (kind === "PYPI") return basename(lockPath).toLowerCase() === "uv.lock" && pythonWorkspaceOwns(root, manifestPath, files);
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
    if (name === "uv.lock" || name === "poetry.lock") return parseToml(value);
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
  if (lockName === "uv.lock") return uvPackageVersion(record(lock) ?? {}, lockPath, manifest, item);
  if (lockName === "poetry.lock") return poetryPackageVersion(record(lock) ?? {}, manifest, item);
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
  if (name === "uv.lock" || name === "poetry.lock") return Array.isArray(record(lock)?.package) ? (record(lock)!.package as unknown[]).length : 0;
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

  for (const manifest of manifests) {
    const parsedGo = manifest.ecosystem === "GO" ? parseGoDependencies(files.get(manifest.path) ?? "") : undefined;
    const directDependencies = parsedGo?.requires ?? manifest.dependencies;
    const external = directDependencies.filter(item => !item.local && !(parsedGo?.replacements.some(candidate => candidate.oldName === item.name && (candidate.oldVersion === undefined || candidate.oldVersion === item.requirement) && candidate.local) ?? false));
    for (const item of external.filter(item => item.registryEligible === false)) limitations.push(`dependency_specifier_unsupported:${manifest.path}:${item.name}`);
    if (manifest.malformed) {
      if (external.length === 0) {
        const unknown = { name: "<manifest>", requirement: "<malformed>", local: false };
        addUnresolved(unresolvedDependencies, unknown, manifest);
        applicableExternalDependencyCount += 1;
      } else for (const item of external) {
        addUnresolved(unresolvedDependencies, item, manifest);
        applicableExternalDependencyCount += 1;
      }
      limitations.push(`dependency_manifest_malformed:${manifest.path}`);
      resolversAttempted.add(manifest.ecosystem);
      continue;
    }
    if (external.length === 0) continue;
    resolversAttempted.add(manifest.ecosystem);
    if (manifest.ecosystem === "PYPI" && isRequirementsPath(manifest.path)) {
      for (const item of external) {
        applicableExternalDependencyCount += 1;
        if (item.registryEligible === false) {
          addUnresolved(unresolvedDependencies, item, manifest, manifest.path);
        } else if (item.exactVersion) {
          exactDependencies.push(exact(item, manifest, item.exactVersion, manifest.path));
        } else {
          addUnresolved(unresolvedDependencies, item, manifest, manifest.path);
          limitations.push(`dependency_version_unresolved:${manifest.path}:${item.name}`);
        }
      }
      continue;
    }
    if (manifest.ecosystem === "GO") {
      const vendorPath = goVendorPathForManifest(manifest.path, candidatePaths);
      const vendorValue = vendorPath === undefined ? undefined : files.get(vendorPath);
      const parsedVendor = vendorValue === undefined ? new Error("dependency_vendor_unavailable") : parseGoVendorModules(vendorValue);
      const vendorConsistent = vendorPath !== undefined && !(parsedVendor instanceof Error) && goVendorConsistent(parsedGo!, parsedVendor);
      if (vendorPath === undefined) limitations.push(`dependency_vendor_missing:${manifest.path}`);
      else if (vendorValue === undefined) limitations.push(`dependency_vendor_unavailable:${vendorPath}`);
      else if (parsedVendor instanceof Error) limitations.push(`${parsedVendor.message}:${vendorPath}`);
      else if (!vendorConsistent) limitations.push(`dependency_vendor_inconsistent:${vendorPath}`);
      for (const item of external) {
        applicableExternalDependencyCount += 1;
        if (!vendorConsistent) {
          addUnresolved(unresolvedDependencies, item, manifest, vendorPath);
          continue;
        }
        const selected = goVendorDependency(item, parsedGo!, parsedVendor);
        if (selected.registryEligible === false) {
          addUnresolved(unresolvedDependencies, item, manifest, vendorPath);
          limitations.push(`dependency_version_unresolved:${manifest.path}:${item.name}`);
        } else {
          exactDependencies.push(exact(selected, manifest, selected.requirement, vendorPath));
        }
      }
      continue;
    }
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
