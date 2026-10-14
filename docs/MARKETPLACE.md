# Circle Agent Marketplace submission

Marketplace publication is separate from deployment. Deploying OMNI does not publish the service automatically.

## Submission copy

Provider: OMNI

Service name: OMNI

Category: INFRASTRUCTURE

Description: Pre-execution trust and risk evidence for autonomous agents before software installation, ERC-8004 agent invocation, or x402 payment, combining supply-chain, ERC-8004 identity/reputation/service, service-identity, payment-history, and licensed threat-intelligence signals.

Suggested tags: `security`, `software-supply-chain`, `x402`, `erc-8004`, `agent-security`, `provenance`

OpenAPI: `https://api.askomni.xyz/openapi.yaml`

Health: `https://api.askomni.xyz/health`
Readiness: `https://api.askomni.xyz/ready`

Payout wallet: use the same `SELLER_ADDRESS` configured in production.

## Evidence to attach

- Unpaid protected request returns HTTP 402 and `PAYMENT-REQUIRED`.
- `circle services inspect` reports price, method, accepted chain(s), and scheme.
- Arc Mainnet paid lifecycle: verified on September 17, 2026 on the tested
  `GET /v1/package/risk` route with a real 5000-atomic / 0.005 USDC x402
  payment on Arc Mainnet (`eip155:5042`), using Circle Agent Wallet + Circle
  Gateway (`https://gateway-api.circle.com`), HTTP 200, durable persistence,
  reconciliation, and replay without duplicate settlement. This does not claim
  exhaustive route-by-route or multi-chain paid acceptance.
- Historical note: Arc Testnet paid lifecycle was verified earlier on the
  tested OMNI paid path, including Circle Agent Wallet payment, Gateway
  settlement, durable persistence, execution, recovery/replay, and Circle
  transfer reconciliation. Historical Testnet evidence is not mainnet evidence.
- Public OpenAPI is reachable.
- `/health` returns process liveness.
- `/ready` returns `status: ready` while reporting non-blocking dependency degradation separately.

## Intake

Submission URL recorded during v0.2 development:
`https://forms.gle/7YFzvdmMcn1JH5tF6`

Verify Circle's current “Get listed” documentation immediately before submission. Treat the URL above as a recorded integration detail, not a permanent marketplace contract.
