import { describe, expect, test } from "bun:test";
import { AGENT_QUICK_TEST_PROMPT } from "../frontend/src/agent-quick-test.ts";
import { API_ENDPOINTS, buildAgentInspectionPrompt, buildRequest, validateInspection, type InspectionInput } from "../frontend/src/agent-inspection-prompt.ts";

const packageInput: InspectionInput = { endpointId: "package", values: { ecosystem: "npm", name: "express", version: "5.2.1" } };
const genericInputs: readonly InspectionInput[] = [
  packageInput,
  { endpointId: "repo", values: { owner: "expressjs", repo: "express" } },
  { endpointId: "dependencies", values: [{ id: 1, ecosystem: "npm", name: "express", version: "5.2.1" }] },
  { endpointId: "preflight", values: { url: "https://example.com/paid" } },
  { endpointId: "agent", values: { chain: "eip155:1", agentId: "42" } },
];

const GROUNDING_RULE = "Report only facts from OMNI JSON or observed payment. Do not infer omitted details or map riskScore to severity. OMNI dimensions are risk levels.";
const EXPECTED_OMNI_SELLER = "0xd5154d79b52a5980e7b0e806f5e4bf3dca3798b5";

describe("agent inspection prompt profiles", () => {
  test("agent builder validates canonical decimal uint256 without Number coercion", () => {
    const validIds = ["0", "1", "42", "115792089237316195423570985008687907853269984665640564039457584007913129639935"];
    for (const agentId of validIds) expect(validateInspection({ endpointId: "agent", values: { chain: "eip155:1", agentId } })).toBeNull();
    for (const agentId of ["01", "-1", "0x2a", "1.5", "115792089237316195423570985008687907853269984665640564039457584007913129639936"]) {
      expect(validateInspection({ endpointId: "agent", values: { chain: "eip155:1", agentId } })).not.toBeNull();
    }
    expect(validateInspection({ endpointId: "agent", values: { chain: "ethereum", agentId: "42" } })).not.toBeNull();
  });

  test("agent request contains only chain and agentId", () => {
    const input: InspectionInput = { endpointId: "agent", values: { chain: "eip155:1", agentId: "42" } };
    const request = buildRequest(input);
    expect(request.url).toBe("https://api.askomni.xyz/v1/agent/risk?chain=eip155%3A1&agentId=42");
    expect(new URL(request.url).searchParams.get("targetUrl")).toBeNull();
  });

  test("homepage quick test is Arc mainnet only", () => {
    expect(AGENT_QUICK_TEST_PROMPT).toContain("Accept: application/json");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("ARC MAINNET ONLY:");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("eip155:5042");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("Circle CLI ARC");
    expect(AGENT_QUICK_TEST_PROMPT).not.toMatch(/eip155:5042002|ARC[- ]TESTNET/);
    expect(AGENT_QUICK_TEST_PROMPT).toContain("No TESTNET or fallback");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("official Circle Agent Wallet");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("https://agents.circle.com/skills/setup.md");
    expect(AGENT_QUICK_TEST_PROMPT).not.toContain("MAINNET only: choose from live PAYMENT-REQUIRED");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("npm:express@5.2.1");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("5000 / 0.005000 USDC");
  });

  test("all API endpoint builders select live MAINNET options", () => {
    for (const input of genericInputs) {
      const prompt = buildAgentInspectionPrompt(input);
      expect(prompt).toContain("Accept: application/json");
      expect(prompt).toContain("MAINNET only: choose from live PAYMENT-REQUIRED");
      expect(prompt).toContain("No TESTNET or fallback");
      expect(prompt).not.toContain("ARC MAINNET ONLY:");
      expect(prompt).not.toContain("eip155:5042002");
      expect(prompt).not.toContain("eip155:5042");
      expect(prompt).not.toContain("TESTNET only:");
    }
  });

  test("payment safety rules remain explicit and compact", () => {
    for (const prompt of [AGENT_QUICK_TEST_PROMPT, ...genericInputs.map(input => buildAgentInspectionPrompt(input))]) {
      expect(prompt).toContain("Send the request unpaid first and read PAYMENT-REQUIRED from HTTP 402");
      expect(prompt).toContain("Select exactly one accepts[] offer");
      expect(prompt).toContain("scheme exact");
      expect(prompt).toContain("asset USDC");
      expect(prompt).toContain("payTo " + EXPECTED_OMNI_SELLER);
      expect(prompt).toContain("All fields must come from that same offer. Never combine offers.");
      expect(prompt).toContain("Require challenge resource to resolve to the same HTTPS origin, path, and query as the original request. Otherwise STOP.");
      expect(prompt).toContain("UUID v4 Idempotency-Key");
      expect(prompt).toContain("Authorize at most one payment");
      expect(prompt).toContain("If validation or payment state is uncertain, STOP");
      expect(prompt).toContain("Never expose wallet/signing/authentication secrets");
    }
  });

  test("prompt sections keep network and payment restrictions in PAYMENT", () => {
    const prompt = buildAgentInspectionPrompt(packageInput);
    const taskStart = prompt.indexOf("TASK\n");
    const requestStart = prompt.indexOf("\nREQUEST\n");
    const paymentStart = prompt.indexOf("\nPAYMENT\n");
    const outputStart = prompt.indexOf("\nOUTPUT\n");
    expect(taskStart).toBe(0);
    expect(taskStart).toBeLessThan(requestStart);
    expect(requestStart).toBeLessThan(paymentStart);
    expect(paymentStart).toBeLessThan(outputStart);

    const requestSection = prompt.slice(requestStart, paymentStart);
    const paymentSection = prompt.slice(paymentStart, outputStart);
    expect(requestSection).toContain("GET https://api.askomni.xyz/v1/package/risk");
    expect(requestSection).toContain("Inspect: npm:express@5.2.1");
    expect(requestSection).not.toContain("TESTNET");
    expect(paymentSection).toContain("MAINNET only:");
  });

  test("resource binding requires the same HTTPS origin, path, and query", () => {
    const prompt = buildAgentInspectionPrompt(packageInput);
    expect(prompt).toContain("Require challenge resource to resolve to the same HTTPS origin, path, and query as the original request. Otherwise STOP.");

    const originalRequestUrl = "https://api.askomni.xyz/v1/package/risk?ecosystem=npm&name=express&version=5.2.1";
    const relativeResources = [
      "/v1/package/risk?version=5.2.1&name=%65xpress&ecosystem=npm",
      "?version=5.2.1&name=%65xpress&ecosystem=npm",
    ];
    for (const resource of relativeResources) {
      const resolvedResource = new URL(resource, originalRequestUrl);
      expect(resolvedResource.origin).toBe(new URL(originalRequestUrl).origin);
      expect(resolvedResource.pathname).toBe(new URL(originalRequestUrl).pathname);
      expect([...resolvedResource.searchParams.entries()].sort()).toEqual([...new URL(originalRequestUrl).searchParams.entries()].sort());
    }
  });

  test("resource mismatches stop before payment", () => {
    const prompt = buildAgentInspectionPrompt(packageInput);
    expect(prompt).toContain("Otherwise STOP");

    const original = new URL("https://api.askomni.xyz/v1/package/risk?ecosystem=npm&name=express&version=5.2.1");
    const mismatches = [
      "https://other.example/v1/package/risk?ecosystem=npm&name=express&version=5.2.1",
      "/v1/repo/risk?ecosystem=npm&name=express&version=5.2.1",
      "/v1/package/risk?ecosystem=npm&name=express&version=5.2.1&extra=true",
      "/v1/package/risk?ecosystem=npm&name=express&version=5.2.2",
    ];
    for (const resource of mismatches) {
      const resolved = new URL(resource, original);
      expect(resolved.origin === original.origin && resolved.pathname === original.pathname && resolved.search === original.search).toBe(false);
    }
  });

  test("agent prompts preserve every endpoint request and price", () => {
    const expectedRequests: readonly { input: InspectionInput; request: string; price: string }[] = [
      {
        input: packageInput,
        request: "GET https://api.askomni.xyz/v1/package/risk?ecosystem=npm&name=express&version=5.2.1",
        price: "5000 / 0.005000 USDC",
      },
      {
        input: genericInputs[1]!,
        request: "GET https://api.askomni.xyz/v1/repo/risk?owner=expressjs&repo=express",
        price: "10000 / 0.010000 USDC",
      },
      {
        input: genericInputs[2]!,
        request: "POST https://api.askomni.xyz/v1/dependencies/risk",
        price: "50000 / 0.050000 USDC",
      },
      {
        input: genericInputs[3]!,
        request: "GET https://api.askomni.xyz/v1/x402/endpoint/preflight?url=https%3A%2F%2Fexample.com%2Fpaid",
        price: "10000 / 0.010000 USDC",
      },
      {
        input: genericInputs[4]!,
        request: "GET https://api.askomni.xyz/v1/agent/risk?chain=eip155%3A1&agentId=42",
        price: "50000 / 0.050000 USDC",
      },
    ];
    expect(expectedRequests).toHaveLength(API_ENDPOINTS.length);

    for (const expected of expectedRequests) {
      const prompt = buildAgentInspectionPrompt(expected.input);
      expect(prompt).toContain(expected.request);
      expect(prompt).toContain(expected.price);
      expect(prompt).toContain("same HTTPS origin, path, and query");
      if (expected.input.endpointId === "dependencies") {
        expect(prompt).toContain("Content-Type: application/json");
        expect(prompt).toContain('"packages": [');
        expect(prompt).toContain('"ecosystem": "npm"');
        expect(prompt).toContain('"name": "express"');
        expect(prompt).toContain('"version": "5.2.1"');
      } else {
        expect(prompt).not.toContain("Content-Type: application/json");
      }
    }
  });

  test("COPY REQUEST and agent prompts use JSON", () => {
    for (const input of genericInputs) {
      const request = buildRequest(input);
      if (input.endpointId !== "agent") {
        expect(request.display).not.toMatch(/MAINNET|TESTNET|eip155:|Gateway/);
        expect(request.curl).not.toMatch(/MAINNET|TESTNET|eip155:|Gateway/);
      }
      expect(request.display).toContain("Accept: application/json");
      expect(request.display).not.toContain("Accept: text/markdown");
      expect(request.curl).toContain("Accept: application/json");
      expect(request.curl).not.toContain("Accept: text/markdown");

      const prompt = buildAgentInspectionPrompt(input);
      expect(prompt).toContain("Accept: application/json");
      expect(prompt).not.toContain("Accept: text/markdown");
    }
  });

  test("preflight never pays the inspected target", () => {
    const prompt = buildAgentInspectionPrompt({ endpointId: "preflight", values: { url: "https://example.com/paid" } });
    expect(prompt).toContain("OMNI is the service being paid");
    expect(prompt).toContain("Never pay the inspected target");
    expect(prompt).toContain("do not create or check wallets for target networks");
  });

  test("scoped npm package names remain intact and URL encoded", () => {
    const request = buildRequest({ endpointId: "package", values: { ecosystem: "npm", name: "@circle-fin/x402-batching", version: "3.3.0" } });
    expect(request.url).toContain("name=%40circle-fin%2Fx402-batching");
    expect(request.url).not.toContain("name=circle-fin%2Fx402-batching");
  });

  test("paid JSON output handles Circle CLI envelopes without another payment", () => {
    const expectedOutput = [
      "OUTPUT",
      "Use only the successful OMNI JSON response. If Circle CLI wraps it, use data.response.",
      "Return a concise risk report. Do not make another paid request.",
    ].join("\n");

    for (const prompt of [AGENT_QUICK_TEST_PROMPT, buildAgentInspectionPrompt(packageInput)]) {
      expect(prompt).toContain(expectedOutput);
      expect(prompt).toContain("Circle CLI");
      expect(prompt).toContain("data.response");
      expect(prompt).toContain("Do not make another paid request");
      expect(prompt).not.toContain("Accept: text/markdown");
      expect(prompt).not.toContain("--quiet");
      expect(prompt).not.toContain("Markdown response body");
      expect(prompt).not.toContain("authoritative OMNI assessment");
      expect(prompt).not.toContain("text/markdown afterward");
      expect(prompt.match(/^TASK$/gm)).toHaveLength(1);
      expect(prompt.match(/^REQUEST$/gm)).toHaveLength(1);
      expect(prompt.match(/^PAYMENT$/gm)).toHaveLength(1);
      expect(prompt.match(/^OUTPUT$/gm)).toHaveLength(1);
    }
  });

  test("grounding rule forbids inferred provenance and riskScore severity mapping", () => {
    for (const prompt of [AGENT_QUICK_TEST_PROMPT, buildAgentInspectionPrompt(packageInput), ...genericInputs.map((input) => buildAgentInspectionPrompt(input))]) {
      expect(prompt).toContain(GROUNDING_RULE);
      expect(prompt).toContain("Do not infer omitted details or map riskScore to severity");
      expect(prompt).toContain("OMNI dimensions are risk levels");
      expect(prompt).not.toContain("RISK LEVELS, not quality ratings. repositorySecurityPractices");
      expect(prompt).not.toContain("repositorySecurityPractices: high means");
      expect(prompt).not.toContain("VERIFIED");
    }
  });

  test("agent prompts omit legacy representation and replay instructions", () => {
    for (const prompt of [AGENT_QUICK_TEST_PROMPT, ...genericInputs.map((input) => buildAgentInspectionPrompt(input))]) {
      expect(prompt).not.toContain("artifact.content");
      expect(prompt).not.toContain("Choose one representation");
      expect(prompt).not.toContain("request JSON then Markdown");
      expect(prompt).not.toContain("replay for Markdown");
      expect(prompt).not.toContain("expect an artifact");
      expect(prompt).not.toContain("second paid request");
      expect(prompt).not.toContain("second copy of the result");
      expect(prompt).not.toContain("never enumerate/use another chain");
      expect(prompt).not.toContain("do not fall back to another chain");
      expect(prompt).not.toContain("do not use another chain");
    }
  });

  test("copied prompts stay bounded", () => {
    const wordCount = (value: string) => value.trim().split(/\s+/).filter(Boolean).length;
    expect(wordCount(AGENT_QUICK_TEST_PROMPT)).toBeLessThan(220);
    expect(wordCount(buildAgentInspectionPrompt(packageInput))).toBeLessThan(220);
  });

  test("Arc quick prompt includes expected payTo validation", () => {
    const prompt = AGENT_QUICK_TEST_PROMPT;
    expect(prompt).toContain(`payTo ${EXPECTED_OMNI_SELLER}`);
    expect(prompt).toContain("Select exactly one accepts[] offer");
  });

  test("Arc quick prompt requires scheme exact", () => {
    const prompt = AGENT_QUICK_TEST_PROMPT;
    expect(prompt).toContain("scheme exact");
  });

  test("Arc quick prompt enforces same-offer field integrity", () => {
    const prompt = AGENT_QUICK_TEST_PROMPT;
    expect(prompt).toContain("All fields must come from that same offer");
    expect(prompt).toContain("Never combine offers");
  });

  test("Arc quick prompt requires eip155:5042", () => {
    const prompt = AGENT_QUICK_TEST_PROMPT;
    expect(prompt).toContain("network eip155:5042");
  });

  test("generic mainnet prompt validates recipient and scheme from selected offer", () => {
    const prompt = buildAgentInspectionPrompt(packageInput);
    expect(prompt).toContain(`payTo ${EXPECTED_OMNI_SELLER}`);
    expect(prompt).toContain("scheme exact");
    expect(prompt).toContain("All fields must come from that same offer");
    expect(prompt).toContain("Never combine offers");
  });

  test("no testnet identifiers in any prompt", () => {
    const allPrompts = [AGENT_QUICK_TEST_PROMPT, ...genericInputs.map(input => buildAgentInspectionPrompt(input))];
    for (const prompt of allPrompts) {
      expect(prompt).not.toContain("eip155:5042002");
      expect(prompt).not.toMatch(/ARC[- ]TESTNET/);
      expect(prompt).not.toContain("TESTNET fallback");
    }
  });

  test("Arc quick prompt requires wallet support Arc and Gateway funds", () => {
    const prompt = AGENT_QUICK_TEST_PROMPT;
    expect(prompt).toContain("wallet to support Arc");
    expect(prompt).toContain("Gateway funds");
  });

  test("generic prompt requires wallet support for selected network", () => {
    const prompt = buildAgentInspectionPrompt(packageInput);
    expect(prompt).toContain("wallet to support the selected network");
    expect(prompt).toContain("Gateway funds");
  });
});
