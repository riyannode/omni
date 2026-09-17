export const OMNI_API_BASE_URL = "https://api.askomni.xyz";
export const MAX_DEPENDENCIES = 100;

export type EndpointId = "package" | "repo" | "dependencies" | "preflight";

export type PackageInput = {
  ecosystem: string;
  name: string;
  version: string;
};

export type RepositoryInput = {
  owner: string;
  repo: string;
};

export type DependencyInput = PackageInput & { id: number };

export type PreflightInput = {
  url: string;
};

export type BuilderValues = {
  package: PackageInput;
  repo: RepositoryInput;
  dependencies: DependencyInput[];
  preflight: PreflightInput;
};

export type InspectionInput =
  | { endpointId: "package"; values: PackageInput }
  | { endpointId: "repo"; values: RepositoryInput }
  | { endpointId: "dependencies"; values: DependencyInput[] }
  | { endpointId: "preflight"; values: PreflightInput };

export type AgentPromptProfile = "generic-mainnet" | "arc-mainnet-quick-test";

export type AgentPromptOptions = {
  profile?: AgentPromptProfile;
};

export type EndpointMetadata = {
  id: EndpointId;
  method: "GET" | "POST";
  path: string;
  price: string;
  displayPrice: string;
  atomicAmount: string;
  copy: string;
};

export const API_ENDPOINTS: readonly EndpointMetadata[] = [
  {
    id: "package",
    method: "GET",
    path: "/v1/package/risk",
    price: "$0.005 USDC",
    displayPrice: "0.005000",
    atomicAmount: "5000",
    copy: "Check package origin, advisories, and release signals before install.",
  },
  {
    id: "repo",
    method: "GET",
    path: "/v1/repo/risk",
    price: "$0.01 USDC",
    displayPrice: "0.010000",
    atomicAmount: "10000",
    copy: "Check repository identity, activity, and risk evidence from named sources.",
  },
  {
    id: "dependencies",
    method: "POST",
    path: "/v1/dependencies/risk",
    price: "$0.05 USDC",
    displayPrice: "0.050000",
    atomicAmount: "50000",
    copy: "Check a dependency set in one request.",
  },
  {
    id: "preflight",
    method: "GET",
    path: "/v1/x402/endpoint/preflight",
    price: "$0.01 USDC",
    displayPrice: "0.010000",
    atomicAmount: "10000",
    copy: "Check service identity and payment details before a paid call.",
  },
];

export type GeneratedRequest = {
  method: "GET" | "POST";
  url: string;
  display: string;
  curl: string;
};

export type RequestRepresentation = "application/json" | "text/markdown";

function trim(value: string): string {
  return value.trim();
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function makeGetRequest(url: string, representation: RequestRepresentation): GeneratedRequest {
  return {
    method: "GET",
    url,
    display: `GET ${url}\nAccept: ${representation}`,
    curl: `curl -sS -X GET ${shellQuote(url)} -H 'Accept: ${representation}'`,
  };
}

function makePostRequest(url: string, body: unknown, representation: RequestRepresentation): GeneratedRequest {
  const json = JSON.stringify(body, null, 2);
  return {
    method: "POST",
    url,
    display: `POST ${url}\nAccept: ${representation}\nContent-Type: application/json\n\n${json}`,
    curl: `curl -sS -X POST ${shellQuote(url)} -H 'Accept: ${representation}' -H 'Content-Type: application/json' --data-raw ${shellQuote(JSON.stringify(body))}`,
  };
}

export function isEndpointId(value: string | null): value is EndpointId {
  return value !== null && API_ENDPOINTS.some((endpoint) => endpoint.id === value);
}

function validatePackageCoordinate(values: PackageInput, subject: string): string | null {
  const ecosystem = trim(values.ecosystem);
  const name = trim(values.name);
  const version = trim(values.version);
  if (!ecosystem) return `Enter an ecosystem for the ${subject}.`;
  if (ecosystem.length > 32) return `${subject} ecosystem must be 32 characters or fewer.`;
  if (!name) return `Enter a package name for the ${subject}.`;
  if (name.length > 256) return `${subject} package name must be 256 characters or fewer.`;
  if (!version) return `Enter a package version for the ${subject}.`;
  if (version.length > 128) return `${subject} version must be 128 characters or fewer.`;
  return null;
}

const REPOSITORY_COMPONENT = /^[A-Za-z0-9_.-]{1,100}$/;

export function validateInspection(input: InspectionInput): string | null {
  if (input.endpointId === "package") return validatePackageCoordinate(input.values, "package");

  if (input.endpointId === "repo") {
    const owner = trim(input.values.owner);
    const repo = trim(input.values.repo);
    if (!owner) return "Enter a repository owner.";
    if (!REPOSITORY_COMPONENT.test(owner)) return "Owner must use 1–100 letters, numbers, dots, underscores, or hyphens.";
    if (!repo) return "Enter a repository name.";
    if (!REPOSITORY_COMPONENT.test(repo)) return "Repository must use 1–100 letters, numbers, dots, underscores, or hyphens.";
    return null;
  }

  if (input.endpointId === "dependencies") {
    if (input.values.length === 0) return "Add at least one dependency.";
    if (input.values.length > MAX_DEPENDENCIES) return `Use ${MAX_DEPENDENCIES} dependencies or fewer.`;
    const incompleteIndex = input.values.findIndex((dependency) => validatePackageCoordinate(dependency, "dependency") !== null);
    if (incompleteIndex === -1) return null;
    const incompleteDependency = input.values[incompleteIndex];
    return incompleteDependency === undefined ? null : validatePackageCoordinate(incompleteDependency, `dependency ${incompleteIndex + 1}`);
  }

  const url = trim(input.values.url);
  if (!url) return "Enter an HTTP or HTTPS URL.";
  if (url.length > 2048) return "Target URL must be 2048 characters or fewer.";
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "Use an HTTP or HTTPS URL.";
  } catch {
    return "Enter a valid HTTP or HTTPS URL.";
  }
  return null;
}

export function buildRequest(input: InspectionInput, representation: RequestRepresentation = "application/json"): GeneratedRequest {
  if (input.endpointId === "package") {
    const query = new URLSearchParams({
      ecosystem: trim(input.values.ecosystem),
      name: trim(input.values.name),
      version: trim(input.values.version),
    });
    return makeGetRequest(`${OMNI_API_BASE_URL}/v1/package/risk?${query.toString()}`, representation);
  }

  if (input.endpointId === "repo") {
    const query = new URLSearchParams({
      owner: trim(input.values.owner),
      repo: trim(input.values.repo),
    });
    return makeGetRequest(`${OMNI_API_BASE_URL}/v1/repo/risk?${query.toString()}`, representation);
  }

  if (input.endpointId === "dependencies") {
    const body = {
      packages: input.values.map(({ ecosystem, name, version }) => ({
        ecosystem: trim(ecosystem),
        name: trim(name),
        version: trim(version),
      })),
    };
    return makePostRequest(`${OMNI_API_BASE_URL}/v1/dependencies/risk`, body, representation);
  }

  const query = new URLSearchParams({ url: trim(input.values.url) });
  return makeGetRequest(`${OMNI_API_BASE_URL}/v1/x402/endpoint/preflight?${query.toString()}`, representation);
}

function targetDescription(input: InspectionInput): string {
  if (input.endpointId === "package") {
    return `${trim(input.values.ecosystem)}:${trim(input.values.name)}@${trim(input.values.version)}`;
  }
  if (input.endpointId === "repo") {
    return `${trim(input.values.owner)}/${trim(input.values.repo)}`;
  }
  if (input.endpointId === "dependencies") {
    const packages = input.values.map(({ ecosystem, name, version }) => `${trim(ecosystem)}:${trim(name)}@${trim(version)}`).join(", ");
    return `the exact dependency set in the JSON body: ${packages}`;
  }
  return trim(input.values.url);
}

type AgentPromptProfileConfig = {
  task: string;
  payment: string;
};

const EXPECTED_OMNI_SELLER = "0xd5154d79b52a5980e7b0e806f5e4bf3dca3798b5";

const AGENT_PROMPT_PROFILES: Record<AgentPromptProfile, AgentPromptProfileConfig> = {
  "generic-mainnet": {
    task: "Use/reuse the official Circle Agent Wallet. Follow https://agents.circle.com/skills/setup.md for setup/login. Ask only for OTP, login, or legal input.",
    payment: "MAINNET only: choose from live PAYMENT-REQUIRED. No TESTNET or fallback.",
  },
  "arc-mainnet-quick-test": {
    task: "Use/reuse the official Circle Agent Wallet. Follow https://agents.circle.com/skills/setup.md for setup/login. Ask only for OTP, login, or legal input.",
    payment: "ARC MAINNET ONLY: use eip155:5042 (Circle CLI ARC). No TESTNET or fallback.",
  },
};

function buildOfferRequirements(profile: AgentPromptProfile, endpoint: EndpointMetadata): string {
  const amount = `${endpoint.atomicAmount} / ${endpoint.displayPrice} USDC`;
  if (profile === "arc-mainnet-quick-test") {
    return `- network eip155:5042
- scheme exact
- asset USDC
- amount ${amount}
- payTo ${EXPECTED_OMNI_SELLER}`;
  }
  return `- scheme exact
- asset USDC
- amount ${amount}
- payTo ${EXPECTED_OMNI_SELLER}`;
}

function buildWalletReadiness(profile: AgentPromptProfile): string {
  if (profile === "arc-mainnet-quick-test") {
    return "Require the wallet to support Arc and have sufficient Gateway funds.";
  }
  return "Require the wallet to support the selected network and have sufficient Gateway funds.";
}

export function buildAgentInspectionPrompt(input: InspectionInput, options: AgentPromptOptions = {}): string {
  const endpoint = API_ENDPOINTS.find((candidate) => candidate.id === input.endpointId);
  if (!endpoint) throw new Error("Unknown OMNI endpoint");
  const profile = AGENT_PROMPT_PROFILES[options.profile ?? "generic-mainnet"];
  const request = buildRequest(input, "application/json");
  const offerRequirements = buildOfferRequirements(options.profile ?? "generic-mainnet", endpoint);
  const walletReadiness = buildWalletReadiness(options.profile ?? "generic-mainnet");
  const preflightRule = input.endpointId === "preflight"
    ? "OMNI is the service being paid; the inspected endpoint URL is input only. Never pay the inspected target. It may advertise TESTNET, MAINNET, or multiple networks; do not reject it merely for MAINNET, and do not create or check wallets for target networks."
    : "";

  return `TASK
${profile.task}

REQUEST
${request.display}
Inspect: ${targetDescription(input)}

PAYMENT
${profile.payment}

Send the request unpaid first and read PAYMENT-REQUIRED from HTTP 402. Body {} is expected.

Select exactly one accepts[] offer and require:
${offerRequirements}

All fields must come from that same offer. Never combine offers.

Require challenge resource to resolve to the same HTTPS origin, path, and query as the original request. Otherwise STOP.

${walletReadiness} Use one fresh UUID v4 Idempotency-Key per logical request. Authorize at most one payment; retries reuse the same request and key. If validation or payment state is uncertain, STOP.

Never expose wallet/signing/authentication secrets.
${preflightRule}

OUTPUT
Use only the successful OMNI JSON response. If Circle CLI wraps it, use data.response.
Return a concise risk report. Do not make another paid request.
Report only facts from OMNI JSON or observed payment. Do not infer omitted details or map riskScore to severity. OMNI dimensions are risk levels.`;
}

export async function copyText(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("Clipboard unavailable");
}
