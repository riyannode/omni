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
                              RiskEngine
                                  |
                         assessment + signals
```

`RiskEngine` is a deep deterministic module. Provider adapters only acquire/normalize evidence. `HistoryStore` owns x402 state-change history. `ThreatIntelStore` owns licensed IOC lookup and is vendor-neutral so commercial data suppliers can be replaced without changing the domain model.

The API process is stateless except for external Valkey/PostgreSQL. Marketplace snapshots run in the worker. Endpoint observations are stored only when their fingerprint changes, making payment/schema/provider drift queryable without writing every poll.

Threat intelligence is intentionally an ingestion seam rather than a hard-coded public feed. Production operators must import data under a license that permits commercial use/derived decisions.
