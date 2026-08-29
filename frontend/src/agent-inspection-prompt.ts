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

export function validateInspection(input: InspectionInput): string | null {
  if (input.endpointId === "package") {
    if (!trim(input.values.ecosystem)) return "Enter an ecosystem.";
    if (!trim(input.values.name)) return "Enter a package name.";
    if (!trim(input.values.version)) return "Enter a package version.";
    return null;
  }

  if (input.endpointId === "repo") {
    if (!trim(input.values.owner)) return "Enter a repository owner.";
    if (!trim(input.values.repo)) return "Enter a repository name.";
    return null;
  }

  if (input.endpointId === "dependencies") {
    if (input.values.length === 0) return "Add at least one dependency.";
    if (input.values.length > MAX_DEPENDENCIES) return `Use ${MAX_DEPENDENCIES} dependencies or fewer.`;
    const incompleteIndex = input.values.findIndex((dependency) => !trim(dependency.ecosystem) || !trim(dependency.name) || !trim(dependency.version));
    return incompleteIndex === -1 ? null : `Complete dependency ${incompleteIndex + 1}.`;
  }

  if (!trim(input.values.url)) return "Enter an HTTP or HTTPS URL.";
  try {
    const parsed = new URL(input.values.url.trim());
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

function requestRepresentation(input: InspectionInput): string {
  if (input.endpointId !== "dependencies") return "Accept: application/json";
  const body = JSON.stringify({
    packages: input.values.map(({ ecosystem, name, version }) => ({
      ecosystem: trim(ecosystem),
      name: trim(name),
      version: trim(version),
    })),
  }, null, 2);
  return `Accept: application/json\n\nContent-Type: application/json\n${body}`;
}

export function buildAgentInspectionPrompt(input: InspectionInput): string {
  const endpoint = API_ENDPOINTS.find((candidate) => candidate.id === input.endpointId);
  if (!endpoint) throw new Error("Unknown OMNI endpoint");
  const request = buildRequest(input);
  const preflightRule = input.endpointId === "preflight"
    ? "- Perform exactly one paid OMNI preflight request only. The target URL is input to OMNI; pay OMNI only to inspect it; do not make a payment request to the target endpoint.\n"
    : "";

  return `Check whether an official Circle Agent Wallet / CLI is already installed, configured, and usable for TESTNET x402.

If it works, reuse it. Do not reinstall Circle tooling or create another wallet.

If it is missing or unusable, run:

curl -sL https://agents.circle.com/skills/setup.md

and follow the official Circle instructions only for the missing setup.

Read:

https://api.askomni.xyz/llms.txt

Then perform exactly one OMNI inspection request:

${request.display}

The user wants OMNI to inspect:
${targetDescription(input)}

Rules:
- TESTNET ONLY. Never use mainnet.
- Create one fresh UUID v4 Idempotency-Key.
- Request without payment first and inspect the real HTTP 402 challenge.
- Pay only if the challenged resource matches the exact OMNI request.
- The payment asset must be USDC.
- Select the network and scheme only from the live HTTP 402 challenge.
- The amount must be exactly ${endpoint.atomicAmount} atomic units = ${endpoint.displayPrice} USDC.
- Use the payment destination from the live challenge; never guess it.
- Authorize at most one ${endpoint.displayPrice} USDC payment.
- Reuse the exact same request and Idempotency-Key for the paid retry.
${input.endpointId === "dependencies" ? "- For the POST request, reuse the exact same JSON body for the paid retry.\n" : ""}${preflightRule}- If payment state is uncertain, stop. Do not retry automatically.
- Never reveal private keys, seed phrases, signing secrets, wallet credentials, or payment authorization secrets.

Request representation:

${requestRepresentation(input)}

After HTTP 200, show the user:

1. JSON Assessment

Show the returned assessment JSON, but omit artifact.content from the JSON display to avoid duplicating the Markdown.

Preserve artifact filename and mediaType and do not invent, infer, rename, or change other returned values.

2. OMNI Markdown Report

Render the returned artifact.content as Markdown.

If artifact.content is unexpectedly missing, report that state and stop.

Do not make another paid request just to obtain Markdown.`;
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
