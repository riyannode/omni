export const AGENT_QUICK_TEST_PROMPT = `Check whether an official Circle Agent Wallet / CLI is already installed, configured, and usable for TESTNET x402.

If it works, reuse it. Do not reinstall Circle tooling or create another wallet.

If it is missing or unusable, run:

curl -sL https://agents.circle.com/skills/setup.md

and follow the official Circle instructions only for the missing setup.

Read:
https://api.askomni.xyz/llms.txt

Then perform exactly one OMNI quick test:

GET https://api.askomni.xyz/v1/package/risk?ecosystem=npm&name=express&version=5.2.1

Rules:
- TESTNET ONLY. Never use mainnet.
- Create one fresh UUID v4 Idempotency-Key.
- Request without payment first and inspect the real HTTP 402 challenge.
- Pay only if the resource matches exactly, the asset is USDC, the selected network/scheme comes from the live challenge, and amount is exactly 5000 atomic units = 0.005000 USDC.
- Use the payment destination from the live challenge; never guess it.
- Authorize at most one 0.005000 USDC payment.
- Reuse the exact same request and Idempotency-Key for the paid retry.
- If payment state is uncertain, stop. Do not retry automatically.
- Never reveal private keys, seed phrases, signing secrets, wallet credentials, or payment authorization secrets.

Request:
Accept: application/json

After HTTP 200, show the user:

1. JSON Assessment
   Show the returned assessment JSON, but omit artifact.content from the JSON display to avoid duplicating the Markdown. Preserve artifact filename and mediaType and do not invent or change other values.

2. OMNI Markdown Report
   Render the returned artifact.content as Markdown.

If artifact.content is unexpectedly missing, report that state and stop.
Do not make another paid request just to obtain Markdown.`;

export async function copyAgentQuickTestPrompt(): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(AGENT_QUICK_TEST_PROMPT);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = AGENT_QUICK_TEST_PROMPT;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("Clipboard unavailable");
}
