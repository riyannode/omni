import { buildAgentInspectionPrompt, copyText, type InspectionInput } from "./agent-inspection-prompt";

const QUICK_TEST_INPUT: InspectionInput = {
  endpointId: "package",
  values: { ecosystem: "npm", name: "express", version: "5.2.1" },
};

export const AGENT_QUICK_TEST_PROMPT = buildAgentInspectionPrompt(QUICK_TEST_INPUT);

export async function copyAgentQuickTestPrompt(): Promise<void> {
  await copyText(AGENT_QUICK_TEST_PROMPT);
}
