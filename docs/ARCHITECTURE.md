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
