# OMNI domain model

OMNI is a pre-execution trust and risk layer for software packages, dependency sets, repositories, and x402 endpoints. It helps a caller decide what follow-up action is appropriate; it does not authorize execution or label an entity malicious without evidence.

## Ubiquitous language

- **Evidence**: a timestamped fact from a named source. Evidence is not a verdict.
- **Snapshot**: normalized evidence for one subject at a point in time.
- **Assessment**: deterministic scoring over a normalized evidence snapshot.
- **Recommendation**: `proceed`, `proceed_with_caution`, `manual_review`, or `do_not_proceed`. This is advisory output, not an authorization decision.
- **Risk score**: integer `0..100`; higher means OMNI observed more decision-relevant risk signals or evidence-source failures. It is not a probability of compromise.
- **Evidence coverage**: `0..1` fraction of the evidence paths expected for that subject type that completed successfully. It is not statistical confidence or a probability of correctness.
- **Health**: `/health` process-liveness response only; it does not assert upstream availability.
- **Readiness**: `/ready` indicates that this replica can accept paid API requests. Non-blocking dependency status is reported separately under `dependencies`.
- **Subject**: package, repository, dependency set, or x402 resource.
- **Provider**: upstream evidence source such as OSV, CISA KEV, OpenSSF Scorecard, or Circle Discovery.
- **Observation**: OMNI-owned historical state, especially x402 payout, network, price, schema, and provider changes.
- **Signal**: structured reason code derived from evidence, such as a known exploited vulnerability, threat-intelligence match, or payout-destination change.
- **Threat intelligence**: licensed IOC data imported into OMNI's vendor-neutral store with source provenance and expiry metadata.
- **Paid route**: an HTTP resource whose handler runs only after the Circle Gateway payment middleware accepts the request.
- **Agent adapter**: optional caller integration for Hermes or another runtime. It does not participate in OMNI scoring or payment verification.
