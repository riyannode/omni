# Reference x402 buyer

The reference caller lives in:

- `src/x402-buyer.ts` — target HTTP flow and payment boundary
- `src/buyer-policy.ts` — pure caller-side purchase policy

The caller keeps OMNI's responsibilities separate:

```text
caller-supplied getPreflight(target)
        ↓
actual target HTTP request
        ↓
HTTP 402 PaymentRequired
        ↓
select one existing accepts[] entry
        ↓
checkX402ChallengeAgainstPreflight()
        ↓
evaluatePurchase()
        ↓
ALLOW → caller-supplied payTarget()
        ↓
external Circle/payment layer
```

## Two payment boundaries

There are two distinct payments:

1. **OMNI preflight acquisition** — the existing paid `GET /v1/x402/endpoint/preflight` route costs `$0.01` and uses the existing Circle seller middleware. The caller-supplied `getPreflight()` boundary may use an external x402 buyer to obtain this advisory result.
2. **External target payment** — the payment for the third-party x402 endpoint. This is the payment governed by `buyer-policy.ts` in this reference integration.

This PR does not implement or execute the OMNI bootstrap payment. It does not claim a fully live two-payment lifecycle unless both payments are separately executed.

## Decision statuses

`evaluatePurchase()` returns an explicit machine-readable status:

- `ALLOW` — consistency matched and every caller policy condition passed. The reference flow may invoke `payTarget()`.
- `DENY` — the recommendation, network, asset, amount, or another caller condition is not acceptable. No target payment is called.
- `RE_PREFLIGHT` — the challenge is stale, mismatched, or has insufficient payment context. The caller must stop and obtain a fresh OMNI preflight. `insufficient_context` is never treated as a match.
- `MANUAL_REVIEW` — the OMNI recommendation is exactly `manual_review`, or evidence coverage is below the caller threshold. No target payment is called.

The exact recommendation mapping is fail-closed:

- `do_not_proceed` → `DENY`
- `manual_review` → `MANUAL_REVIEW`
- another recommendation not in `allowedRecommendations` → `DENY`

Network and asset checks are caller-owned. Atomic amounts are validated with the existing `canonicalAtomicAmount()` and compared as `BigInt`; decimal, exponent, negative, and malformed values cannot produce `ALLOW`.

The selector must return the exact `PaymentRequirements` object from the parsed `PaymentRequired.accepts[]` array. The reference caller does not synthesize, rewrite, cross-combine, or automatically switch payment options.

Malformed decoded `PaymentRequired` data and invalid policy/evidence-coverage ranges fail closed as `DENY`; they never reach `payTarget()`.

The reference buyer runs in the caller/runtime and performs the target request directly; it is not an OMNI proxy. OMNI's existing `X402Probe` remains responsible for server-side preflight endpoint safety, including HTTPS and private/link-local address rejection. A production caller should apply its own target allowlist/network policy before passing a target to this reference flow; this module intentionally does not duplicate OMNI probe logic or silently rewrite the target.

`checkX402ChallengeAgainstPreflight()` remains the authoritative implementation for preflight freshness, resource matching, offered-entry membership, atomic amount normalization, EVM address comparison, and Circle Gateway metadata consistency. OMNI scoring and seller middleware remain unchanged. Wallet authorization, signing, and settlement stay in the external caller/payment layer.
