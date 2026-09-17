import { describe, expect, test } from "bun:test";
import { AGENT_QUICK_TEST_PROMPT } from "../frontend/src/agent-quick-test.ts";
import { API_ENDPOINTS, buildAgentInspectionPrompt, buildRequest, type InspectionInput } from "../frontend/src/agent-inspection-prompt.ts";

const packageInput: InspectionInput = { endpointId: "package", values: { ecosystem: "npm", name: "express", version: "5.2.1" } };
const genericInputs: readonly InspectionInput[] = [
  packageInput,
  { endpointId: "repo", values: { owner: "expressjs", repo: "express" } },
  { endpointId: "dependencies", values: [{ id: 1, ecosystem: "npm", name: "express", version: "5.2.1" }] },
  { endpointId: "preflight", values: { url: "https://example.com/paid" } },
];

const GROUNDING_RULE = "Report only facts present in OMNI JSON or directly observed during payment. Do not infer omitted details or map riskScore to a severity. OMNI dimension values are risk levels, not quality ratings.";
const EXPECTED_OMNI_SELLER = "0xd5154d79b52a5980e7b0e806f5e4bf3dca3798b5";

describe("agent inspection prompt profiles", () => {
  test("homepage quick test is Arc mainnet only", () => {
    expect(AGENT_QUICK_TEST_PROMPT).toContain("Accept: application/json");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("ARC MAINNET ONLY:");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("eip155:5042");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("Circle CLI chain ARC");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("If eip155:5042 is absent from PAYMENT-REQUIRED, STOP.");
    expect(AGENT_QUICK_TEST_PROMPT).not.toMatch(/eip155:5042002|ARC[- ]TESTNET/);
    expect(AGENT_QUICK_TEST_PROMPT).toContain("No TESTNET.");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("no other chain, no network fallback");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("If the Arc mainnet wallet is not payment-ready or its Gateway balance cannot cover the payment, STOP.");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("official Circle Agent Wallet");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("https://agents.circle.com/skills/setup.md");
    expect(AGENT_QUICK_TEST_PROMPT).not.toContain("MAINNET only: choose one acceptable Circle-supported MAINNET option actually advertised by the live challenge");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("npm:express@5.2.1");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("5000 atomic units / 0.005000 USDC");
  });

  test("all API endpoint builders select live MAINNET options", () => {
    for (const input of genericInputs) {
      const prompt = buildAgentInspectionPrompt(input);
      expect(prompt).toContain("Accept: application/json");
      expect(prompt).toContain("MAINNET only: choose one acceptable Circle-supported MAINNET option actually advertised by the live challenge");
      expect(prompt).toContain("No TESTNET use or fallback.");
      expect(prompt).toContain("If the selected wallet does not support that network, is not payment-ready, or lacks Gateway funds, STOP.");
      expect(prompt).not.toContain("ARC MAINNET ONLY:");
      expect(prompt).not.toContain("eip155:5042002");
      expect(prompt).not.toContain("eip155:5042");
      expect(prompt).not.toContain("TESTNET only:");
      expect(prompt).toContain("not a static allowlist");
      expect(prompt).toContain("If none, STOP.");
    }
  });

  test("payment safety rules remain explicit and compact", () => {
    for (const prompt of [AGENT_QUICK_TEST_PROMPT, ...genericInputs.map(input => buildAgentInspectionPrompt(input))]) {
      expect(prompt).toContain("Send the request unpaid first; on 402 read the PAYMENT-REQUIRED header and status. Body {} is valid.");
      expect(prompt).toContain("Require asset USDC and exactly");
      expect(prompt).toContain("one fresh UUID v4 Idempotency-Key per logical request");
      expect(prompt).toContain("Authorize at most one payment; any retry reuses the same request and key.");
      expect(prompt).toContain("If validation, wallet/Gateway funds, or payment state is uncertain: STOP.");
      expect(prompt).toContain("Never expose authentication, wallet, signing, or payment secrets.");
      expect(AGENT_QUICK_TEST_PROMPT).not.toContain("Retry same method, URL, POST body, and Idempotency-Key");
      expect(AGENT_QUICK_TEST_PROMPT).not.toContain("never re-pay automatically");
      expect(AGENT_QUICK_TEST_PROMPT).not.toContain("OTP, wallet");
      expect(AGENT_QUICK_TEST_PROMPT).not.toContain("payment authorization secrets");
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
    expect(requestSection).not.toContain("payment-ready");
    expect(paymentSection).toContain("MAINNET only:");
    expect(paymentSection).toContain("payment-ready");
  });

  test("resource binding requires the same HTTPS origin, pathname, and query", () => {
    const prompt = buildAgentInspectionPrompt(packageInput);
    expect(prompt).toContain("Require the challenge resource to resolve (new URL(challengeResource, originalRequestUrl)) to the same HTTPS origin, pathname, and query names/values as the full original OMNI request URL");
    expect(prompt).toContain("no missing/extra keys (order and equivalent percent-encoding are okay)");
    expect(prompt).toContain("Otherwise STOP before payment.");
    expect(prompt).not.toContain("Different origin, pathname, query key, or query value: STOP before payment");

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
    expect(prompt).toContain("Otherwise STOP before payment");

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
        price: "5000 atomic units / 0.005000 USDC",
      },
      {
        input: genericInputs[1]!,
        request: "GET https://api.askomni.xyz/v1/repo/risk?owner=expressjs&repo=express",
        price: "10000 atomic units / 0.010000 USDC",
      },
      {
        input: genericInputs[2]!,
        request: "POST https://api.askomni.xyz/v1/dependencies/risk",
        price: "50000 atomic units / 0.050000 USDC",
      },
      {
        input: genericInputs[3]!,
        request: "GET https://api.askomni.xyz/v1/x402/endpoint/preflight?url=https%3A%2F%2Fexample.com%2Fpaid",
        price: "10000 atomic units / 0.010000 USDC",
      },
    ];
    expect(expectedRequests).toHaveLength(API_ENDPOINTS.length);

    for (const expected of expectedRequests) {
      const prompt = buildAgentInspectionPrompt(expected.input);
      expect(prompt).toContain(expected.request);
      expect(prompt).toContain(expected.price);
      expect(prompt).toContain("new URL(challengeResource, originalRequestUrl)");
      expect(prompt).toContain("same HTTPS origin, pathname, and query names/values");
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
      expect(request.display).not.toMatch(/MAINNET|TESTNET|eip155:|Gateway/);
      expect(request.curl).not.toMatch(/MAINNET|TESTNET|eip155:|Gateway/);
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
      "Use only the successful paid OMNI JSON response; if Circle CLI returns an envelope, unwrap data.response.",
      "Return a concise human-readable risk report. Do not make another paid request or request another representation.",
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
      expect(prompt).toContain("Report only facts present in OMNI JSON or directly observed during payment.");
      expect(prompt).toContain("Do not infer omitted details or map riskScore to a severity.");
      expect(prompt).toContain("OMNI dimension values are risk levels, not quality ratings.");
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

  test("copied prompts stay bounded with Circle CLI response handling", () => {
    const wordCount = (value: string) => value.trim().split(/\s+/).filter(Boolean).length;
    expect(wordCount(AGENT_QUICK_TEST_PROMPT)).toBeLessThan(320);
    expect(wordCount(buildAgentInspectionPrompt(packageInput))).toBeLessThan(320);
  });

  test("Arc quick prompt includes expected payTo validation", () => {
    const prompt = AGENT_QUICK_TEST_PROMPT;
    expect(prompt).toContain(`payTo must be ${EXPECTED_OMNI_SELLER}`);
    expect(prompt).toContain("Validate the selected offer as one complete offer from PAYMENT-REQUIRED");
  });

  test("Arc quick prompt requires scheme exact", () => {
    const prompt = AGENT_QUICK_TEST_PROMPT;
    expect(prompt).toContain("scheme must be exact");
  });

  test("Arc quick prompt enforces same-offer field integrity", () => {
    const prompt = AGENT_QUICK_TEST_PROMPT;
    expect(prompt).toContain("asset/amount/network must come from the same offer entry");
    expect(prompt).toContain("Never combine fields from different accepts[] entries");
  });

  test("Arc quick prompt requires exact offer match or STOP", () => {
    const prompt = AGENT_QUICK_TEST_PROMPT;
    expect(prompt).toContain("If the offer does not match exactly, STOP");
  });

  test("generic mainnet prompt validates recipient and scheme from selected offer", () => {
    const prompt = buildAgentInspectionPrompt(packageInput);
    expect(prompt).toContain(`payTo must be ${EXPECTED_OMNI_SELLER}`);
    expect(prompt).toContain("scheme must be exact");
    expect(prompt).toContain("asset/amount/network must come from the same offer entry");
    expect(prompt).toContain("Never combine fields from different accepts[] entries");
    expect(prompt).toContain("If payTo is not the expected seller or scheme is not exact, STOP");
  });

  test("no testnet identifiers in any prompt", () => {
    const allPrompts = [AGENT_QUICK_TEST_PROMPT, ...genericInputs.map(input => buildAgentInspectionPrompt(input))];
    for (const prompt of allPrompts) {
      expect(prompt).not.toContain("eip155:5042002");
      expect(prompt).not.toMatch(/ARC[- ]TESTNET/);
      expect(prompt).not.toContain("TESTNET fallback");
    }
  });
});
