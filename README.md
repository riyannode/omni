# OMNI 
[![Accepts Agent Payments](https://agents.circle.com/sell/score/badge?url=api.askomni.xyz)](https://agents.circle.com/sell/score?url=api.askomni.xyz)

OMNI is a **pre-execution trust and risk layer for autonomous agents**. OMNI independently verifies what an autonomous agent is about to trust before execution or payment, returning deterministic, source-attributed risk evidence.

OMNI is runtime-agnostic: Hermes, Codex, Claude, OpenClaw, MCP clients, CI, or plain HTTP clients can consume the same API. Circle CLI/Agent Wallet is the recommended buyer-wallet path; the seller uses Circle's official `@circle-fin/x402-batching` middleware.

## What OMNI evaluates

Three intelligence planes feed one deterministic `RiskEngine`:

1. **Supply-chain intelligence** — OSV vulnerabilities, CISA KEV known exploitation, npm registry lifecycle/integrity/maintainer metadata, OpenSSF repository security practices, and licensed package IOC matches.
2. **Service/identity intelligence** — Circle Discovery identity, safe x402 handshake observations, provider/schema history, and licensed URL/hostname IOC matches.
3. **Payment intelligence** — x402 payout address/network/price history, payout-destination changes, and licensed wallet IOC matches.

OMNI does **not** equate “not found in a threat feed” with “safe”. Results expose `evidenceCoverage`, `signals`, `sourceErrors`, and an advisory `recommendation`.

## Production API

The current production API is `https://api.askomni.xyz`. Source-hosted `openapi.yaml` and `llms.txt` retain a runtime template URL; deployed responses render that template with the configured public base URL.

## Trust before execution

```text
Agent proposes → OMNI verifies → caller policy decides → wallet enforces → Circle settles
```

The agent and the x402 endpoint are not trusted blindly. OMNI verifies available evidence; the caller, user, or runtime decides what conditions are acceptable; the wallet or runtime enforces that policy; and Circle remains the payment/settlement rail. OMNI does not authorize payment. It does not guarantee endpoint behaviour or determine user-specific economic utility.

For x402, a marketplace listing or earlier preflight is evidence, not authority. The caller can compare the selected execution-time `PaymentRequirements` from the actual HTTP 402 challenge with `preflightContext.paymentOptions` observed by OMNI before payment. The comparison can produce `match`, `repreflight_required`, or `insufficient_context`; it is advisory and local.

## Paid endpoints

| Endpoint | Price | Purpose |
|---|---:|---|
| `GET /v1/package/risk` | `$0.005` | Exact package/version risk before install |
| `GET /v1/repo/risk` | `$0.01` | Repository security-practice evidence |
| `POST /v1/dependencies/risk` | `$0.05` | Up to 100 exact dependency assessments |
| `GET /v1/x402/endpoint/preflight` | `$0.01` | Service + payment preflight before an agent pays |

Request path: **validate → admission control → durable paid-request reservation → persist payment-attempt identity → official Circle payment gate/settlement → cached evidence → RiskEngine → durable JSON result**. Validation, admission, and initial durable-store failures happen before settlement; post-settlement persistence failures fail closed into durable recovery. Paid calls require a UUID v4 `Idempotency-Key`; retries of one logical request must reuse the same key, while a different request with that key returns a conflict.

Successful paid results keep the canonical structured assessment fields inline. The default response, `Accept: application/json`, and `Accept: */*` additionally include an additive deterministic Markdown artifact payload (`filename`, `mediaType: text/markdown`, and `content`) generated from that same canonical result. Fixed service filenames are `package.risk.md`, `repo.risk.md`, `dependencies.risk.md`, and `x402.endpoint.preflight.md`; they are never derived from user-controlled targets. Callers that send `Accept: text/markdown` receive only the deterministic Markdown rendering. Artifact-capable clients may materialize the supplied filename/content; OMNI does not write client files. Unsupported or zero-quality `Accept` values return HTTP 406 before payment. The representation is selected at the HTTP response seam, `Vary: Accept` is returned, and replaying a completed request in another representation does not execute or settle again. Payment errors remain JSON.

## Data sources

Built-in network sources are OSV, CISA KEV, npm Registry, OpenSSF Scorecard, and Circle Discovery. Repository assessments also use GitHub repository evidence and deps.dev observations; a configured `GITHUB_TOKEN` enables authenticated GitHub reads for higher upstream limits. The KEV loader tries `www.cisa.gov` first and falls back to the `cisagov/kev-data` mirror, because some egress ranges receive HTTP 403 from cisa.gov; override the ordered list with `OMNI_KEV_FEED_URLS`. The resolved `feedUrl` and `catalogVersion` are reported in the evidence detail. OMNI-owned PostgreSQL history accumulates endpoint/provider/schema/payment configuration changes over time. OpenSSF Scorecard reports `available`, `not_indexed`, `unavailable`, or `error`; `not_indexed` means that no Scorecard result is indexed for the repository, not that the provider is generally unavailable.

Commercial threat feeds are deliberately **not hard-coded**. `threat_indicators` is a vendor-neutral IOC store for URL, hostname, wallet, and package indicators. Import only data whose license permits your commercial use and derived API responses. This avoids coupling OMNI's business to a feed whose terms prohibit redistribution.

```bash
DATABASE_URL=... bun scripts/import-threat-intel.ts licensed-indicators.ndjson
```

Each NDJSON row:

```json
{"indicatorType":"wallet","indicator":"0xabc...","threatType":"reported_malicious","severity":"high","source":"licensed-feed","reference":"case-123"}
```

If no licensed feed is loaded, `/ready` reports `threatIntelligence: "unconfigured"` and relevant assessments cannot claim full evidence coverage. Repository dependency threat intelligence is an observation-only evidence path under `omni-risk-v1`; it does not directly change the repository score or recommendation.

OSV `MAL-*` records are returned separately as `maliciousPackageObservations`. They are not normal vulnerability findings, OMNI does not invent a severity for them, and they remain observation-only under `omni-risk-v1`; explicitly withdrawn MAL records are not returned as active observations.

`RepositoryEvidence` is an internal typed evidence foundation used by the assessment implementation and journal. It is not a top-level field on the public `RiskAssessment` response.

## Stack

- Bun 1.3.14
- TypeScript 7 strict mode
- Express 5.2.1
- `@circle-fin/x402-batching` 3.3.0
- PostgreSQL 18.4
- Valkey 9.1.1 through Bun's native Redis client
- Zod 4.4.3

## Local start

```bash
cp .env.example .env
# Set a non-zero testnet SELLER_ADDRESS.
bun install

docker compose up -d postgres valkey
bun run db:init
bun run dev
```

Health endpoints are `GET /health` and `GET /ready`. `openapi.yaml` is served at `/openapi.yaml`, and a machine-readable integration guide for agents is served at `/llms.txt`.

Buyer clients can compare the selected official x402 `PaymentRequirements` from a `PaymentRequired` response with the configuration observed during preflight (`preflightContext.paymentOptions`) and request a fresh assessment when they differ. Circle Gateway observations retain `maxTimeoutSeconds` and observed `extra.name`, `extra.version`, and `extra.verifyingContract`; atomic amounts are integer strings with no floating-point or exponent normalization. A match is consistency evidence, not payment authorization; see `/llms.txt`.

## Maturity

This repository is a production-shaped MVP, not a proven production deployment. The API/payment architecture is real, and durable paid-request recovery/idempotency is verified against the PostgreSQL-backed recovery path. Real Arc Testnet x402 paid lifecycle has been verified on the tested OMNI paid path, including Circle Agent Wallet payment, Gateway settlement, durable persistence, execution, recovery/replay, and Circle transfer reconciliation. This does not claim exhaustive route-by-route paid acceptance, mainnet readiness, multi-chain support, or fleet capacity. Remaining work includes licensed threat-feed contracts, distributed observability, provider quota/circuit-breaker validation, security isolation, broader route acceptance, and measured fleet load/soak tests. The high concurrent paid-call figure remains a horizontal capacity objective, not a verified throughput claim.

See `docs/PRD.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/SCALE.md`, and `docs/MARKETPLACE.md`.
