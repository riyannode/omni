# OMNI architecture

OMNI keeps agent runtime, payment verification, evidence acquisition and scoring separate.

```text
Agent / Circle CLI / MCP
          |
          v
HTTP validation -> admission gate -> Circle x402 seller middleware
                                      |
                                      v
                              OmniIntelligence
                     /             |             \
             supply chain     service identity    payment/history
                     \             |             /
                              RiskSnapshot
                                  |
                              RiskFeatures
                                  |
                    RiskEngine + versioned RiskPolicy
                                  |
                         assessment + signals
                                  |
                   best-effort AssessmentJournal
```

`RiskEngine` is a deep deterministic module. Provider adapters only acquire/normalize evidence. Repository assessment first resolves a GitHub ref to an immutable commit SHA (re-resolved on every request so branch movement is observed), and only the immutable commit identity may enter the assessment cache; the expensive tree/file collection runs once per commit, not per branch lookup. Each `package.json` is paired deterministically with its same-directory lockfile (`package-lock.json`, `npm-shrinkwrap.json`, or `bun.lock`); declarations whose lock association cannot be proven are reported as unresolved with partial coverage instead of being resolved against an unrelated lock. Security manifests from ecosystems OMNI does not resolve (PyPI, Cargo, Go) are detected and reported as `dependency_resolution_unsupported:<ECOSYSTEM>` limitations rather than silently counted as covered. Per-package deps.dev observations (`dependencyObservations`: coordinate, licenses, advisory IDs, graph status, provenance) are typed fields of `RepositoryEvidence` so a future bounded repository-audit agent consumes them without parsing generic evidence detail. Repository evidence coverage/limitations/source errors are observation-only under `omni-risk-v1` and never alter the existing Scorecard-based score/recommendation. Offline evaluation replays current-cohort rows plus historical v1 package/x402/dependency_set rows (their feature extraction is semantically unchanged); v1 repository rows remain incompatible because replaying them would reinterpret historical evidence under the new optional fields. `HistoryStore` owns x402 state-change history. `ThreatIntelStore` owns licensed IOC lookup and is vendor-neutral so commercial data suppliers can be replaced without changing the domain model.

The API process is stateless except for external Valkey/PostgreSQL. Marketplace snapshots run in the worker. Endpoint observations are stored only when their fingerprint changes, making payment/schema/provider drift queryable without writing every poll.

Threat intelligence is intentionally an ingestion seam rather than a hard-coded public feed. Production operators must import data under a license that permits commercial use/derived decisions.

Assessment records retain the normalized snapshot, deterministic features, assessment, and explicit schema/policy versions. Independent outcome labels are stored separately and are never inferred from OMNI output. Offline evaluation/calibration replays labelled history against candidate policies; later shadow scorers may observe the same features, but cannot change authoritative recommendations. Promotion is explicit, manually controlled, versioned, reversible, and benchmarked.

## Caller-side enforcement integration

The caller may place an optional runtime policy gate after OMNI returns its assessment. This is outside the OMNI implementation:

```text
                         OMNI verification seam
                                  │
Agent / Runtime ───────► OMNI HTTP interface
                                  │
                         evidence acquisition
                                  │
                         deterministic assessment
                                  │
                            advisory result
                                  │
                                  ▼
                         Runtime / Policy Gate
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                 allow                      hold / deny
                    │
                    ▼
               Agent Wallet
                    │
                    ▼
                x402 payment
                    │
                    ▼
             Circle settlement rail
```

For x402, the caller compares the OMNI preflight observation with the actual selected `PaymentRequirements` from the HTTP 402 challenge before applying local policy. A match is consistency evidence only. A stale or mismatched result should lead to re-preflight or caller-side denial; insufficient context must not be treated as a match.

`RiskEngine` is authoritative only for the deterministic OMNI assessment. It is not authoritative for user spending authorization, wallet execution, settlement, or user-specific utility/economic-value decisions. No wallet logic belongs in `OmniIntelligence` or `RiskEngine`.

The structured assessment is the canonical result. The HTTP response seam returns that result as JSON by default with an additive deterministic Markdown artifact payload selected by fixed service identity, or as pure deterministic Markdown when the caller requests `Accept: text/markdown`; durable storage and replay always retain only the structured result, so representation/artifact delivery never triggers another payment or execution. Artifact-capable callers may materialize the supplied filename/content; OMNI does not write caller files.

## Paid request recovery

Paid routes require a caller-supplied UUID v4 `Idempotency-Key`. The validated request is fingerprinted and, once a payment signature is present, reserved atomically in PostgreSQL. The payment-attempt identity and EIP-3009 nonce are persisted before the official Circle Gateway middleware can settle.

```text
validated request
        ↓
durable logical request reservation
        ↓
persist EIP-3009 nonce / payment-attempt identity
        ↓
official Circle settlement
        ↓
persist Circle transfer identity / paid state
        ↓
OmniIntelligence
        ↓
durable final JSON result
        ↓
completed → replay result
```

Recovery is explicit: `completed` replays; `paid` or stale `running` resumes without payment; `settling` or `recovery_pending` reconciles with Circle by nonce. An exact accepted transfer marks the request paid and resumes execution. Unknown, ambiguous, mismatching, unavailable, or failed recovery never initiates another settlement.

Real Arc Testnet x402 paid lifecycle has been verified on the tested OMNI paid path, including Circle Agent Wallet payment, Gateway settlement, durable PostgreSQL persistence, execution, recovery/replay, and Circle transfer reconciliation. Broader route-by-route acceptance, mainnet readiness, multi-chain support, and fleet validation remain separate gates.
