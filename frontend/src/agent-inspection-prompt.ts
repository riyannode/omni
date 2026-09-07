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

export type AgentPromptProfile = "generic-testnet" | "arc-testnet-quick-test";

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

function trim(value: string): string {
  return value.trim();
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function makeGetRequest(url: string): GeneratedRequest {
  return {
    method: "GET",
    url,
    display: `GET ${url}\nAccept: application/json`,
    curl: `curl -sS -X GET ${shellQuote(url)} -H 'Accept: application/json'`,
  };
}

function makePostRequest(url: string, body: unknown): GeneratedRequest {
  const json = JSON.stringify(body, null, 2);
  return {
    method: "POST",
    url,
    display: `POST ${url}\nAccept: application/json\nContent-Type: application/json\n\n${json}`,
    curl: `curl -sS -X POST ${shellQuote(url)} -H 'Accept: application/json' -H 'Content-Type: application/json' --data-raw ${shellQuote(JSON.stringify(body))}`,
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

export function buildRequest(input: InspectionInput): GeneratedRequest {
  if (input.endpointId === "package") {
    const query = new URLSearchParams({
      ecosystem: trim(input.values.ecosystem),
      name: trim(input.values.name),
      version: trim(input.values.version),
    });
    return makeGetRequest(`${OMNI_API_BASE_URL}/v1/package/risk?${query.toString()}`);
  }

  if (input.endpointId === "repo") {
    const query = new URLSearchParams({
      owner: trim(input.values.owner),
      repo: trim(input.values.repo),
    });
    return makeGetRequest(`${OMNI_API_BASE_URL}/v1/repo/risk?${query.toString()}`);
  }

  if (input.endpointId === "dependencies") {
    const body = {
      packages: input.values.map(({ ecosystem, name, version }) => ({
        ecosystem: trim(ecosystem),
        name: trim(name),
        version: trim(version),
      })),
    };
    return makePostRequest(`${OMNI_API_BASE_URL}/v1/dependencies/risk`, body);
  }

  const query = new URLSearchParams({ url: trim(input.values.url) });
  return makeGetRequest(`${OMNI_API_BASE_URL}/v1/x402/endpoint/preflight?${query.toString()}`);
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

const AGENT_PROMPT_PROFILES: Record<AgentPromptProfile, AgentPromptProfileConfig> = {
  "generic-testnet": {
    task: "Use/reuse official Circle Agent Wallet. If setup/login needed, follow https://agents.circle.com/skills/setup.md. Ask only for OTP, login, or legal input.",
    payment: "TESTNET only: choose acceptable TESTNET option from challenge; if none, STOP. If the selected TESTNET wallet is not payment-ready or its Gateway balance cannot cover the payment, STOP; do not fall back to another chain.",
  },
  "arc-testnet-quick-test": {
    task: "Use/reuse official Circle Agent Wallet. For setup/login, follow https://agents.circle.com/skills/setup.md. Ask only for OTP, login, legal input.",
    payment: "ARC TESTNET ONLY: select eip155:5042002; never enumerate/use another chain. If absent, STOP. If the Arc Testnet wallet is not payment-ready or its Gateway balance cannot cover the payment, STOP; do not use another chain.",
  },
};

const RESOURCE_VALIDATION_RULE = `Resolve new URL(challengeResource, originalRequestUrl) against full original OMNI request URL. Require same HTTPS origin, pathname, and query names/values; no missing/extra keys. Query order and equivalent percent-encoding are okay. Different origin, pathname, query key, or query value: STOP before payment.`;

const UNPAID_REQUEST_RULE = "Make request unpaid first. Check HTTP status and PAYMENT-REQUIRED header; body {} is allowed.";

export function buildAgentInspectionPrompt(input: InspectionInput, options: AgentPromptOptions = {}): string {
  const endpoint = API_ENDPOINTS.find((candidate) => candidate.id === input.endpointId);
  if (!endpoint) throw new Error("Unknown OMNI endpoint");
  const profile = AGENT_PROMPT_PROFILES[options.profile ?? "generic-testnet"];
  const request = buildRequest(input);
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
${UNPAID_REQUEST_RULE}
Require asset USDC and exactly ${endpoint.atomicAmount} atomic units / ${endpoint.displayPrice} USDC.
${RESOURCE_VALIDATION_RULE}
Use one fresh UUID v4 Idempotency-Key. Authorize at most one payment. Retry same method, URL, POST body, and Idempotency-Key. If payment state is uncertain, STOP; never re-pay automatically.
Never expose OTP, wallet, signing, or payment authorization secrets.
${preflightRule}

OUTPUT
After HTTP 200:
1. Show JSON without artifact.content.
2. Render artifact.content as the human-readable OMNI Markdown Report.
Missing content: report and stop; no more paid requests.`;
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
