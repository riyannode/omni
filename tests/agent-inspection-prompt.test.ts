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

describe("agent inspection prompt profiles", () => {
  test("homepage quick test is Arc Testnet only", () => {
    expect(AGENT_QUICK_TEST_PROMPT).toContain("Accept: application/json");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("ARC TESTNET ONLY:");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("eip155:5042002");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("never enumerate/use another chain");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("If the Arc Testnet wallet is not payment-ready or its Gateway balance cannot cover the payment, STOP; do not use another chain.");
    expect(AGENT_QUICK_TEST_PROMPT).not.toContain("TESTNET only: choose an acceptable TESTNET option");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("npm:express@5.2.1");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("5000 atomic units / 0.005000 USDC");
  });

  test("all API endpoint builders keep generic TESTNET behavior", () => {
    for (const input of genericInputs) {
      const prompt = buildAgentInspectionPrompt(input);
      expect(prompt).toContain("Accept: application/json");
      expect(prompt).toContain("TESTNET only:");
      expect(prompt).toContain("acceptable TESTNET option");
      expect(prompt).toContain("If the selected TESTNET wallet is not payment-ready or its Gateway balance cannot cover the payment, STOP; do not fall back to another chain.");
      expect(prompt).not.toContain("or cannot cover the payment");
      expect(prompt).not.toContain("ARC TESTNET ONLY:");
      expect(prompt).not.toContain("eip155:5042002");
    }
  });

  test("payment safety rules remain explicit and compact", () => {
    expect(AGENT_QUICK_TEST_PROMPT).toContain("one fresh UUID v4 Idempotency-Key");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("HTTP status and PAYMENT-REQUIRED header");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("body {} is allowed");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("Authorize at most one payment");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("same method, URL, POST body, and Idempotency-Key");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("If payment state is uncertain, STOP");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("never re-pay automatically");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("asset USDC");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("Never expose OTP, wallet, signing, or payment authorization secrets.");
    expect(AGENT_QUICK_TEST_PROMPT).not.toContain("Never expose secrets");
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
    expect(paymentSection).toContain("TESTNET only:");
    expect(paymentSection).toContain("payment-ready");
  });

  test("resource validation is semantic and resolves relative resources against the full request URL", () => {
    const prompt = buildAgentInspectionPrompt(packageInput);
    expect(prompt).toContain("new URL(challengeResource, originalRequestUrl)");
    expect(prompt).toContain("full original OMNI request URL");
    expect(prompt).toContain("same HTTPS origin, pathname, and query names/values");
    expect(prompt).toContain("Query order and equivalent percent-encoding are okay");
    expect(prompt).not.toContain("must match the exact OMNI request");

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
    expect(prompt).toContain("Different origin, pathname, query key, or query value: STOP before payment");

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
      "After the paid call succeeds, use the OMNI JSON service result returned by the paid request.",
      "If Circle CLI returns an envelope, use data.response as the OMNI service result. Treat that compact JSON as the authoritative OMNI assessment. Present it to the user as a concise human-readable risk report.",
      "Do not request text/markdown afterward. Do not make another paid request.",
    ].join("\n");

    for (const prompt of [AGENT_QUICK_TEST_PROMPT, buildAgentInspectionPrompt(packageInput)]) {
      expect(prompt).toContain(expectedOutput);
      expect(prompt).toContain("Circle CLI");
      expect(prompt).toContain("data.response");
      expect(prompt).toContain("authoritative OMNI assessment");
      expect(prompt).toContain("concise human-readable risk report");
      expect(prompt).not.toContain("Accept: text/markdown");
      expect(prompt).not.toContain("--quiet");
      expect(prompt).not.toContain("Markdown response body");
      expect(prompt).not.toContain("second representation");
      expect(prompt).not.toContain("second paid request");
      expect(prompt.match(/^TASK$/gm)).toHaveLength(1);
      expect(prompt.match(/^REQUEST$/gm)).toHaveLength(1);
      expect(prompt.match(/^PAYMENT$/gm)).toHaveLength(1);
      expect(prompt.match(/^OUTPUT$/gm)).toHaveLength(1);
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
    }
  });

  test("copied prompts stay bounded with Circle CLI response handling", () => {
    const wordCount = (value: string) => value.trim().split(/\s+/).filter(Boolean).length;
    expect(wordCount(AGENT_QUICK_TEST_PROMPT)).toBeLessThan(250);
    expect(wordCount(buildAgentInspectionPrompt(packageInput))).toBeLessThan(250);
  });
});
