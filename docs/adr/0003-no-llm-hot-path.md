# ADR 0003 — No LLM in core paid assessments

Status: accepted.

Decision: core endpoints use normalized evidence + deterministic `RiskEngine`. An LLM can later create explanations or deep research asynchronously as a separate premium product.

Why: bounded model-related cost and latency, reproducible scoring, simpler regression testing, and fewer runtime dependencies in the high-concurrency request path.
