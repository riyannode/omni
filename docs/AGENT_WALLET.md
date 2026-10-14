# Circle Agent Wallet integration for OMNI

The buyer agent wallet is separate from the OMNI seller process. OMNI only needs the existing seller payout address. Buyer payments are signed through the wallet/runtime; no buyer private key belongs in the OMNI server. This guide does not select a buyer address or authorize funding, deposits, or payments.

## Production configuration and acceptance

Mainnet-ready production configuration targets:

```dotenv
CIRCLE_FACILITATOR_URL=https://gateway-api.circle.com
```

Production facilitator selection is controlled at runtime by `CIRCLE_FACILITATOR_URL`; the Arc mainnet target is `https://gateway-api.circle.com`. Keep `SELLER_ADDRESS` and endpoint prices unchanged.

- Arc Mainnet paid lifecycle: verified on September 17, 2026 on the tested
  `GET /v1/package/risk` route with a real 5000-atomic / 0.005 USDC x402
  payment on Arc Mainnet (`eip155:5042`), using Circle Agent Wallet + Circle
  Gateway (`https://gateway-api.circle.com`), HTTP 200, durable persistence,
  reconciliation, and replay without duplicate settlement. Remaining acceptance
  gates include broader route coverage, multi-chain acceptance, fleet
  validation, and capacity testing.
- Historical note: Arc Testnet paid lifecycle was verified earlier on the
  tested OMNI paid path. Historical Testnet evidence is not mainnet evidence.

## Setup/login

Use/reuse the official Circle Agent Wallet. Follow the current official setup/login instructions at https://agents.circle.com/skills/setup.md. Mainnet and testnet sessions are separate. Inspect existing wallets before creating anything else. Never write OTPs, Circle session files, private keys, or mnemonics into the repository.

## General API / COPY AGENT PROMPT

The `generic-mainnet` profile is MAINNET-only, not Arc-only:

1. Send the exact OMNI request unpaid first with `Accept: application/json`. On HTTP 402, read PAYMENT-REQUIRED; an empty JSON body is valid. An Idempotency-Key is optional for unpaid discovery.
2. Select any acceptable Circle-supported MAINNET option actually offered by the live challenge. Arc, Base, Unichain, Polygon, or another Circle-supported mainnet may be acceptable only when offered; this list is not proof of availability. No testnet use or fallback. If none is acceptable, STOP.
3. The wallet must support that network, be payment-ready, and have enough Gateway balance for the exact USDC payment. Otherwise STOP. Validate the selected offer's network, scheme, asset, amount, and recipient together; never combine fields from different offers.
4. Resolve the challenge resource against the original OMNI URL. Require the same HTTPS origin, path, and query names/values with no missing/extra keys (order and equivalent percent-encoding are okay). Otherwise STOP before payment.
5. Use one fresh UUID v4 `Idempotency-Key` per logical request. Authorize at most one payment; an allowed retry reuses the same request and key. Uncertain validation, funds, or payment state requires STOP. Never expose authentication, wallet, signing, or payment secrets.

Prices remain: package `5000` atomic units / `0.005000` USDC; repository and x402 preflight `10000` / `0.010000`; dependency set `50000` / `0.050000`; agent risk `50000` / `0.050000`.

For `/v1/agent/risk`, the `chain` query parameter selects the ERC-8004 identity/reputation chain. It does not select the Circle payment network used to purchase the OMNI request. Payment network selection remains based on the live `PAYMENT-REQUIRED` challenge. The existing Arc Mainnet acceptance above applies to `GET /v1/package/risk` only; no live-paid acceptance is claimed for the agent route. No Arc Mainnet ERC-8004 deployment or support is claimed.

For x402 preflight, OMNI is the service being paid and the inspected URL is input only. Never pay the inspected target as part of the OMNI request.

## TRY WITH YOUR AGENT

The homepage uses `arc-mainnet-quick-test`: ARC MAINNET ONLY, exactly `eip155:5042`, Circle CLI chain `ARC`. No other network or fallback. If `eip155:5042` is absent from PAYMENT-REQUIRED, the Arc mainnet wallet is not payment-ready, or Gateway balance cannot cover the payment, STOP. All shared payment and reporting rules above apply. This profile is not an API-wide network requirement.

## Report output

Use only successful OMNI JSON as the report source. If Circle CLI returns an envelope, unwrap data.response. Return a concise human-readable risk report. Do not make another paid request or request another representation.

Report only facts present in OMNI JSON or directly observed during payment. Do not infer omitted details or map riskScore to a severity. OMNI dimension values are risk levels, not quality ratings.

## Isolated development only

The optional `https://gateway-api-testnet.circle.com` override in `.env.example` is for local/isolated testnet testing, never production. Historical Arc Testnet tests used `ARC-TESTNET` / `eip155:5042002`; those identifiers are not production buyer guidance. Planned testnet load ramps do not establish mainnet acceptance or capacity.

Keep buyer-wallet automation and seller deployment credentials operationally separate even when managed from the same Circle account.
