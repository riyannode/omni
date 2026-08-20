# ADR 0001 — OMNI core is independent of agent runtime

Status: accepted.

Decision: expose HTTP/OpenAPI as the primary interface. Hermes and other agent runtimes are adapters/callers.

Why: the data product should remain usable when a caller changes model/runtime, and the paid request path should not depend on LLM-provider availability.
