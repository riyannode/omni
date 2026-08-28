export const AGENT_QUICK_TEST_PROMPT = `Run:

curl -sL https://agents.circle.com/skills/setup.md

and follow the returned official Circle setup instructions to set up an agent wallet.

Then read OMNI's agent documentation:

https://api.askomni.xyz/llms.txt

and OpenAPI specification:

https://api.askomni.xyz/openapi.yaml

After setup, perform exactly ONE bounded OMNI quick test using:

GET https://api.askomni.xyz/v1/package/risk?ecosystem=npm&name=express&version=5.2.1

This quick test costs exactly:

0.005000 USDC

Rules:

1. TESTNET ONLY.
   Never use mainnet funds for this quick test.

2. Generate one fresh UUID v4 Idempotency-Key.

3. First send the request without payment.
4. Inspect the real HTTP 402 Payment Required challenge returned by OMNI.

5. Confirm before payment that:
   - the requested resource matches the package-risk endpoint;
   - the requested amount is exactly 0.005000 USDC;
   - the payment scheme is one advertised by the live challenge;
   - the payment network is one advertised by the live challenge.

6. Do not assume Arc Testnet is the only supported network.
   Prefer Arc Testnet only if:
   - it is advertised by the live challenge; and
   - the wallet is funded there.

7. Authorize at most ONE payment for this task.

8. For THIS quick test only, never authorize more than:
   0.005000 USDC.

9. Reuse the exact same request and exact same Idempotency-Key for the paid retry.

10. Do not generate a new idempotency key after payment.

11. Return the final OMNI JSON assessment.

12. Show:
    - riskScore
    - recommendation
    - evidenceCoverage
    - policyVersion
    - sourceErrors
    - important source-attributed evidence
    - artifact metadata if present

13. Never reveal:
    - private key
    - seed phrase
    - signing secret
    - wallet credential
    - API credential
    - payment authorization secret

14. If the wallet has no funds on any TESTNET network advertised by the live challenge:
    - do not substitute mainnet funds;
    - follow only official Circle funding/faucet guidance returned by the Circle setup instructions;
    - otherwise stop and report what funding step is required.

15. If payment state becomes uncertain:
    - do not automatically retry payment;
    - stop and report the uncertain state.

16. Do not test any other paid OMNI endpoint during this task.

For reference only, OMNI currently also exposes:

- repository risk: $0.01 USDC
- dependency-set risk: $0.05 USDC
- x402 endpoint preflight: $0.01 USDC

Those services are outside this quick test and must not be paid for during this task.`;

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
