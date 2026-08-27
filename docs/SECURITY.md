# OMNI security model

- Circle payment verification/settlement is delegated to official `@circle-fin/x402-batching`; OMNI never receives buyer private keys.
- Request validation and replica admission happen before the payment middleware.
- External evidence is untrusted and normalized before scoring. Missing evidence is surfaced, never treated as proof of low risk.
- x402 active probes are HTTPS-only, reject private/loopback/link-local targets, disable redirects, and only probe Circle-listed or explicitly allowlisted hosts. Production still needs egress NetworkPolicy/proxy isolation.
- Non-GET marketplace resources are not actively invoked during preflight.
- Threat feeds must be commercially licensed for the intended use. Store source/reference provenance and honor expiry/retention terms.
- A shared payout wallet, changed schema, new maintainer, install script, or marketplace absence is a **risk signal**, not standalone proof of malicious intent.

## Trust-boundary implications

- Agent-provided intent is untrusted input.
- An endpoint's payment challenge and service response are untrusted input.
- A marketplace listing is evidence, not authority.
- An OMNI assessment does not grant spending authority or authorize a payment.
- Wallet/runtime code must independently enforce its local policy.
- A stale preflight is not proof of the execution-time payment configuration.
- A mismatch between preflight and the actual selected payment requirements should trigger re-preflight or caller-side denial.
- Insufficient evidence or comparison context must not be interpreted as a successful match.
- OMNI does not guarantee endpoint behaviour, prevent every loss, or decide whether a purchase is economically worthwhile for a specific user.

## Paid failure semantics

- Package and endpoint provider failures may become `sourceErrors` and reduce coverage where the current implementation does so. Repository dependency ThreatIntel failures remain in repository observation detail and do not become generic scoring inputs under `omni-risk-v1`. Repository ThreatIntel remains observation-only. Scorecard `not_indexed` means that no indexed result exists for the repository; it is not a generic provider outage. Paid routes use durable idempotency, settlement reconciliation by EIP-3009 nonce, and persisted result recovery. This provides effectively-once paid-request behavior for known logical keys; it does not claim mathematical exactly-once semantics across PostgreSQL and Circle. Uncertain recovery fails closed rather than charging again.
