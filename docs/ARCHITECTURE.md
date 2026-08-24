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

`RiskEngine` is a deep deterministic module. Provider adapters only acquire/normalize evidence. `HistoryStore` owns x402 state-change history. `ThreatIntelStore` owns licensed IOC lookup and is vendor-neutral so commercial data suppliers can be replaced without changing the domain model.

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
