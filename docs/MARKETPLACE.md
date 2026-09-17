# Circle Agent Marketplace submission

Marketplace publication is separate from deployment. Deploying OMNI does not publish the service automatically.

## Submission copy

Provider: OMNI

Service name: OMNI

Category: INFRASTRUCTURE

Description: Pre-execution trust and risk evidence for autonomous agents before software installation or x402 payment, combining supply-chain, service-identity, payment-history, and licensed threat-intelligence signals.

Suggested tags: `security`, `software-supply-chain`, `x402`, `agent-security`, `provenance`

OpenAPI: `https://api.askomni.xyz/openapi.yaml`

Health: `https://api.askomni.xyz/health`
Readiness: `https://api.askomni.xyz/ready`

Payout wallet: use the same `SELLER_ADDRESS` configured in production.

## Evidence to attach

- Unpaid protected request returns HTTP 402 and `PAYMENT-REQUIRED`.
- `circle services inspect` reports price, method, accepted chain(s), and scheme.
- Historical acceptance evidence (Arc Testnet paid lifecycle: verified historically): a real Arc Testnet x402 paid call on the tested OMNI paid path returned HTTP 200 with non-mocked Circle Agent Wallet payment, Gateway settlement, durable persistence, execution, recovery/replay, and Circle transfer reconciliation. This does not claim exhaustive route-by-route or mainnet paid acceptance.
- Arc Mainnet paid lifecycle: verified on a real eip155:5042 x402 payment on the package-risk route, including Gateway-funded payment, successful OMNI execution, durable persistence, reconciliation, and replay without duplicate settlement. Production facilitator selection is controlled at runtime by `CIRCLE_FACILITATOR_URL`; the Arc mainnet target is `https://gateway-api.circle.com`. This does not claim exhaustive route-by-route or multi-chain paid acceptance. Capture additional route coverage evidence before advertising broader mainnet paid acceptance. General API buyers select acceptable mainnet options from the live PAYMENT-REQUIRED challenge; the Arc-only quick test is not an API contract requirement.
- Public OpenAPI is reachable.
- `/health` returns process liveness.
- `/ready` returns `status: ready` while reporting non-blocking dependency degradation separately.

## Intake

Submission URL recorded during v0.2 development:
`https://forms.gle/7YFzvdmMcn1JH5tF6`

Verify Circle's current “Get listed” documentation immediately before submission. Treat the URL above as a recorded integration detail, not a permanent marketplace contract.
