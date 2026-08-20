# OMNI security model

- Circle payment verification/settlement is delegated to official `@circle-fin/x402-batching`; OMNI never receives buyer private keys.
- Request validation and replica admission happen before the payment middleware.
- External evidence is untrusted and normalized before scoring. Missing evidence is surfaced, never treated as proof of low risk.
- x402 active probes are HTTPS-only, reject private/loopback/link-local targets, disable redirects, and only probe Circle-listed or explicitly allowlisted hosts. Production still needs egress NetworkPolicy/proxy isolation.
- Non-GET marketplace resources are not actively invoked during preflight.
- Threat feeds must be commercially licensed for the intended use. Store source/reference provenance and honor expiry/retention terms.
- A shared payout wallet, changed schema, new maintainer, install script, or marketplace absence is a **risk signal**, not standalone proof of malicious intent.

## Paid failure semantics

Expected provider failures become `sourceErrors` and reduce coverage. Unexpected runtime failure after settlement is not yet durably recoverable in v0.2; post-payment idempotency/result persistence is required before a production-readiness claim.
