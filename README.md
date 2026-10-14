# OMNI 
[![Accepts Agent Payments](https://agents.circle.com/sell/score/badge?url=api.askomni.xyz)](https://agents.circle.com/sell/score?url=api.askomni.xyz)

OMNI is a **pre-execution trust and risk layer for autonomous agents**. OMNI independently verifies what an autonomous agent is about to trust before execution or payment, returning deterministic, source-attributed risk evidence.

OMNI is runtime-agnostic: Hermes, Codex, Claude, OpenClaw, MCP clients, CI, or plain HTTP clients can consume the same API. Circle CLI/Agent Wallet is the recommended buyer-wallet path; the seller uses Circle's official `@circle-fin/x402-batching` middleware.

## What OMNI evaluates

Three intelligence planes feed one deterministic `RiskEngine`:

1. **Supply-chain intelligence** — OSV vulnerabilities, CISA KEV known exploitation, npm registry lifecycle/integrity/maintainer metadata, OpenSSF repository security practices, and licensed package IOC matches.
2. **Service/identity intelligence** — Circle Discovery identity, safe x402 handshake observations, ERC-8004 IdentityRegistry and ReputationRegistry evidence, verified registration/agent-card evidence, advertised service observations, and licensed URL/hostname IOC matches.
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

The current source and API contract define five paid endpoints.

| Endpoint | Price | Purpose |
|---|---:|---|
| `GET /v1/package/risk` | `$0.005` | Exact package/version risk before install |
| `GET /v1/repo/risk` | `$0.01` | Repository security-practice evidence |
| `POST /v1/dependencies/risk` | `$0.05` | Up to 100 exact dependency assessments |
| `GET /v1/x402/endpoint/preflight` | `$0.01` | Service + payment preflight before an agent pays |
| `GET /v1/agent/risk` | `$0.05` | ERC-8004 agent identity, reputation, and registration integrity |

OMNI's paid API can be purchased over any compatible mainnet option currently offered by the live Circle Gateway x402 challenge. For `/v1/agent/risk`, `chain` selects the ERC-8004 identity/reputation chain; it does not select the Circle payment network. Payment selection still comes from the live `PAYMENT-REQUIRED` challenge. Production identity chains currently include Ethereum Mainnet and Base Mainnet; no Arc Mainnet ERC-8004 deployment or support is claimed. Arc Mainnet is the pinned network only for the Try with your agent demo flow.

Agent risk contract semantics: ERC-8004 ReputationRegistry data is raw public evidence, not an OMNI trust score. `identity.status` is factual (`REGISTERED`, `NOT_REGISTERED`, `UNAVAILABLE`); `reputationSummary.status` is factual (`OBSERVED`, `ABSENT`, `UNAVAILABLE`, `UNKNOWN`); and `agentIdentity`, `agentReputation`, and `agentRegistration` use only `low`, `medium`, `high`, `critical`, or `unknown`. Public feedback can be observed while `agentReputation` remains `unknown` when no policy-qualified evidence scores. Production trusted-reviewer/tag policy remains empty until provenance and semantics are defensible. `/v1/agent/risk` accepts only `chain` and `agentId`; service endpoint verification remains `/v1/x402/endpoint/preflight`, and `targetUrl` is rejected.

Request path: **validate → admission control → durable paid-request reservation → persist payment-attempt identity → official Circle payment gate/settlement → cached evidence → RiskEngine → durable JSON result**. Validation, admission, and initial durable-store failures happen before settlement; post-settlement persistence failures fail closed into durable recovery. Paid calls require a UUID v4 `Idempotency-Key`; retries of one logical request must reuse the same key, while a different request with that key returns a conflict.

Successful paid results keep the canonical structured assessment fields inline. `Accept: application/json` is the compact machine/agent interface; it contains authoritative decision fields, bounded scoring-relevant signals, repository summaries, bounded package `MAL-*` observation counts, coverage, bounded source errors, freshness, and explicit omission counts. It does **not** contain `artifact`, Markdown, raw `evidence[]`, provider payloads, full advisory objects, or full dependency lists. `Accept: text/markdown` is a concise deterministic human summary; it is not a second copy of the JSON payload and never serializes raw evidence details. Unsupported or zero-quality `Accept` values return HTTP 406 before payment. The representation is selected at the HTTP response seam, `Vary: Accept` is returned, and replaying a completed request in another representation does not execute or settle again. Payment errors remain JSON.

## Data sources

Built-in network sources are OSV, CISA KEV, npm Registry, OpenSSF Scorecard, Circle Discovery, and ERC-8004 registries. ERC-8004 IdentityRegistry and ReputationRegistry reads are on-chain evidence; registration URI and agent-card/service metadata are off-chain evidence. Reputation contributes to scoring only when feedback satisfies the configured trusted-reviewer/tag policy. Repository assessments also use GitHub repository evidence and deps.dev observations. Exact repository dependencies resolved from supported NPM/Cargo lockfiles, exact `requirements*.txt` pins, authoritative `pyproject.toml` + uv/Poetry locks, and proven selected Go module snapshots from `vendor/modules.txt` are queried against OSV as `npm`, `crates.io`, `PyPI`, and `Go`; bare `go.mod` requirements remain minimum-version evidence and are unresolved without vendor selection proof; CVE IDs from successful OSV observations are correlated with CISA KEV in one bounded repository lookup. Unresolved or deferred dependencies remain explicitly uncertain, and unsupported formats are not silently broadened. A configured `GITHUB_TOKEN` enables authenticated GitHub reads for higher upstream limits. The KEV loader tries `www.cisa.gov` first and falls back to the `cisagov/kev-data` mirror, because some egress ranges receive HTTP 403 from cisa.gov; override the ordered list with `OMNI_KEV_FEED_URLS`. The resolved `feedUrl` and `catalogVersion` are reported in the evidence detail. OMNI-owned PostgreSQL history accumulates endpoint/provider/schema/payment configuration changes over time. OpenSSF Scorecard reports `available`, `not_indexed`, `unavailable`, or `error`; `not_indexed` means that no Scorecard result is indexed for the repository, not that the provider is generally unavailable.

Commercial threat feeds are deliberately **not hard-coded**. `threat_indicators` is a vendor-neutral IOC store for URL, hostname, wallet, and package indicators. Import only data whose license permits your commercial use and derived API responses. This avoids coupling OMNI's business to a feed whose terms prohibit redistribution.

```bash
DATABASE_URL=... bun scripts/import-threat-intel.ts licensed-indicators.ndjson
```

Each NDJSON row:

```json
{"indicatorType":"wallet","indicator":"0xabc...","threatType":"reported_malicious","severity":"high","source":"licensed-feed","reference":"case-123"}
```

If no licensed feed is loaded, `/ready` reports `threatIntelligence: "unconfigured"` and relevant package assessments report that source as `UNAVAILABLE` under the versioned `package-coverage-v2` model. Repository assessments report the same missing feed under `repository-coverage-v1`; it contributes uncertainty and recommendation gating, not a direct risk penalty. Observed exact dependency matches can contribute deterministic repository threat-intelligence risk.

OSV `MAL-*` records are returned separately as `maliciousPackageObservations`. They are not normal vulnerability findings and OMNI does not invent an OSV severity for them. An active exact-version MAL observation can trigger the deterministic repository malicious-package policy risk; explicitly withdrawn MAL records are not returned as active observations.

Repository risk uses the strongest-observed-risk model: security practices, dependency vulnerabilities, explicit CISA KEV matches, active MAL-* observations, and licensed dependency threat-intelligence matches are aggregated with `MAX`, not added by finding count. Missing evidence, provider failures, unresolved or deferred dependencies, and partial collection remain coverage/score-status uncertainty and do not directly increase `riskScore`; partial evidence can still gate the recommendation to `manual_review`.

`RepositoryEvidence` is an internal typed evidence foundation used by the assessment implementation and journal. It is not a top-level field on the public `RiskAssessment` response.

## Stack

- Bun 1.3.14
- TypeScript 7 strict mode
- Express 5.2.1
- `@circle-fin/x402-batching` 3.5.0
- PostgreSQL 18.4
- Valkey 9.1.1 through Bun's native Redis client
- Zod 4.4.3

## Local start

```bash
cp .env.example .env
# Set the existing non-zero SELLER_ADDRESS and Circle mainnet facilitator.
bun install

docker compose up -d postgres valkey
bun run db:init
bun run dev
```

Health endpoints are `GET /health` and `GET /ready`. `openapi.yaml` is served at `/openapi.yaml`, and a machine-readable integration guide for agents is served at `/llms.txt`.

Buyer clients can compare the selected official x402 `PaymentRequirements` from a `PaymentRequired` response with the configuration observed during preflight (`preflightContext.paymentOptions`) and request a fresh assessment when they differ. Circle Gateway observations retain `maxTimeoutSeconds` and observed `extra.name`, `extra.version`, and `extra.verifyingContract`; atomic amounts are integer strings with no floating-point or exponent normalization. A match is consistency evidence, not payment authorization; see `/llms.txt`.

## Arc Mainnet — Verified Paid Lifecycle

- Date: September 17, 2026
- Network: Arc Mainnet / `eip155:5042`
- Tested paid route: `GET /v1/package/risk`
- Real x402 amount: `5000` atomic / `0.005` USDC
- Payment path: Circle Agent Wallet + Circle Gateway
- Production facilitator: `https://gateway-api.circle.com`
- HTTP result: `200`
- OMNI assessment executed
- Result durably persisted
- Payment/request reconciliation passed
- Replay of the same logical request returned the completed result
- Replay did not create a duplicate settlement

Scope: this verifies the tested `package-risk` paid lifecycle on Arc Mainnet. It does not claim that every OMNI paid route or every supported mainnet network has been paid-tested. No live-paid production acceptance, production migration, or persistence verification is claimed for `/v1/agent/risk`.

### Mainnet payment behavior

OMNI exposes the mainnet payment options returned by Circle Gateway through the live x402 PAYMENT-REQUIRED challenge.

The general agent flow dynamically selects a compatible mainnet offer from the live challenge rather than relying on a static network allowlist.

The Try with your agent demo is intentionally pinned to Arc Mainnet (`eip155:5042`) to provide a deterministic Arc-specific test flow.

At the September 17, 2026 production verification, the live challenge exposed 12 mainnet payment options, including Arc Mainnet.

## Maturity

OMNI is deployed and operating in production on Arc mainnet. The API/payment architecture is real, and durable paid-request recovery/idempotency is verified against the PostgreSQL-backed recovery path.

Historical note: the Arc Testnet paid lifecycle was verified earlier on the tested OMNI paid path, including Circle Agent Wallet payment, Gateway settlement, durable persistence, execution, recovery/replay, and Circle transfer reconciliation. Historical Testnet evidence is not mainnet evidence.

Remaining work includes licensed threat-feed contracts, distributed observability, provider quota/circuit-breaker validation, security isolation, broader route-by-route acceptance, multi-chain acceptance, fleet-scale validation, and measured load/soak testing. The high concurrent paid-call figure remains a horizontal capacity objective, not a verified throughput claim.

See `docs/PRD.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/SCALE.md`, and `docs/MARKETPLACE.md`.

## License

OMNI is licensed under the [MIT License](LICENSE).
