import { describe, expect, test } from "bun:test";
import { AGENT_QUICK_TEST_PROMPT } from "../frontend/src/agent-quick-test.ts";
import { buildAgentInspectionPrompt, buildRequest, type InspectionInput } from "../frontend/src/agent-inspection-prompt.ts";

const packageInput: InspectionInput = { endpointId: "package", values: { ecosystem: "npm", name: "express", version: "5.2.1" } };
const genericInputs: readonly InspectionInput[] = [
  packageInput,
  { endpointId: "repo", values: { owner: "expressjs", repo: "express" } },
  { endpointId: "dependencies", values: [{ id: 1, ecosystem: "npm", name: "express", version: "5.2.1" }] },
  { endpointId: "preflight", values: { url: "https://example.com/paid" } },
];

describe("agent inspection prompt profiles", () => {
  test("homepage quick test is Arc Testnet only", () => {
    expect(AGENT_QUICK_TEST_PROMPT).toContain("ARC TESTNET ONLY:");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("eip155:5042002");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("never enumerate/use another chain");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("If the Arc Testnet wallet or Gateway balance cannot cover the payment, STOP; do not use another chain.");
    expect(AGENT_QUICK_TEST_PROMPT).not.toContain("TESTNET only: choose an acceptable TESTNET option");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("npm:express@5.2.1");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("5000 atomic units / 0.005000 USDC");
  });

  test("all API endpoint builders keep generic TESTNET behavior", () => {
    for (const input of genericInputs) {
      const prompt = buildAgentInspectionPrompt(input);
      expect(prompt).toContain("TESTNET only:");
      expect(prompt).toContain("acceptable TESTNET option");
      expect(prompt).toContain("If the selected TESTNET wallet is not payment-ready or cannot cover the payment, STOP; do not fall back to another chain.");
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

  test("copied prompts stay materially shorter", () => {
    const wordCount = (value: string) => value.trim().split(/\s+/).filter(Boolean).length;
    expect(wordCount(AGENT_QUICK_TEST_PROMPT)).toBeLessThanOrEqual(180);
    expect(wordCount(buildAgentInspectionPrompt(packageInput))).toBeLessThanOrEqual(180);
  });
});
