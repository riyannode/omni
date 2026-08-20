# Circle Agent Marketplace submission

Marketplace publication is separate from deployment. Deploying OMNI does not publish the service automatically.

## Submission copy

Provider: OMNI

Service name: OMNI

Category: INFRASTRUCTURE

Description: Pre-execution trust and risk evidence for autonomous agents before software installation or x402 payment, combining supply-chain, service-identity, payment-history, and licensed threat-intelligence signals.

Suggested tags: `security`, `software-supply-chain`, `x402`, `agent-security`, `provenance`

OpenAPI: `https://<production-host>/openapi.yaml`

Health: `https://<production-host>/health`
Readiness: `https://<production-host>/ready`

Payout wallet: use the same `SELLER_ADDRESS` configured in production.

## Evidence to attach

- Unpaid protected request returns HTTP 402 and `PAYMENT-REQUIRED`.
- `circle services inspect` reports price, method, accepted chain(s), and scheme.
- A testnet paid call with non-mocked Circle settlement returns HTTP 200 before mainnet launch.
- Public OpenAPI is reachable.
- `/health` returns process liveness.
- `/ready` returns `status: ready` while reporting non-blocking dependency degradation separately.

## Intake

Submission URL recorded during v0.2 development:
`https://forms.gle/7YFzvdmMcn1JH5tF6`

Verify Circle's current “Get listed” documentation immediately before submission. Treat the URL above as a recorded integration detail, not a permanent marketplace contract.
