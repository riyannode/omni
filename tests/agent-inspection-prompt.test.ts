import { describe, expect, test } from "bun:test";
import { AGENT_QUICK_TEST_PROMPT } from "../frontend/src/agent-quick-test.ts";
import { buildAgentInspectionPrompt, type InspectionInput } from "../frontend/src/agent-inspection-prompt.ts";

const genericInputs: readonly InspectionInput[] = [
  { endpointId: "package", values: { ecosystem: "npm", name: "express", version: "5.2.1" } },
  { endpointId: "repo", values: { owner: "expressjs", repo: "express" } },
  { endpointId: "dependencies", values: [{ id: 1, ecosystem: "npm", name: "express", version: "5.2.1" }] },
  { endpointId: "preflight", values: { url: "https://example.com/paid" } },
];

describe("agent inspection prompt profiles", () => {
  test("homepage quick test uses Arc Testnet without generic network fallback", () => {
    expect(AGENT_QUICK_TEST_PROMPT).toContain("Set up or reuse an official Circle Agent Wallet for ARC TESTNET x402.");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("ARC TESTNET ONLY.");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("Expected network: eip155:5042002.");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("Use only the Arc Testnet payment option from the live HTTP 402 challenge.");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("Do not inspect, enumerate, or try any other chain.");
    expect(AGENT_QUICK_TEST_PROMPT).toContain("Do not automatically fall back to another network.");
    expect(AGENT_QUICK_TEST_PROMPT).not.toContain("- TESTNET ONLY.");
    expect(AGENT_QUICK_TEST_PROMPT).not.toContain("Network, scheme, asset, and payTo come from the live challenge.");
  });

  test("all API endpoint builders keep generic Testnet behavior", () => {
    for (const input of genericInputs) {
      const prompt = buildAgentInspectionPrompt(input);
      expect(prompt).toContain("Set up or reuse an official Circle Agent Wallet for TESTNET x402.");
      expect(prompt).toContain("If a usable TESTNET wallet already exists, reuse it.");
      expect(prompt).toContain("- TESTNET ONLY.");
      expect(prompt).toContain("Network, scheme, asset, and payTo come from the live challenge.");
      expect(prompt).not.toContain("ARC TESTNET ONLY.");
      expect(prompt).not.toContain("eip155:5042002");
    }
  });
});
