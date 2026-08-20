# ADR 0002 — Circle Gateway nanopayments are the default seller rail

Status: accepted.

Decision: use Circle-maintained `@circle-fin/x402-batching` middleware. Do not hand-roll EIP-3009, EIP-712, verification, or settlement.

Why: OMNI is a sub-cent/high-frequency agent API, matching Circle's Gateway nanopayment path. Vanilla x402 can be added later if distribution proves it is needed.
