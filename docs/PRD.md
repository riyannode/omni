# OMNI PRD — v0.3

## Product thesis

Autonomous agents increasingly install third-party software, call paid services, and authorize machine payments. Existing controls are fragmented: vulnerability databases answer software questions, marketplace discovery answers listing questions, and wallet policies bound spend, but the agent still lacks one machine-consumable pre-execution risk decision layer.

OMNI answers one question before a consequential action: **what evidence says this install/call/payment deserves caution right now?**

## Trust model

Neither the autonomous agent nor the third-party endpoint is inherently trusted.

```text
Agent proposes an action
        ↓
Endpoint supplies service and payment requirements
        ↓
OMNI independently evaluates available evidence
        ↓
OMNI returns a deterministic assessment
        ↓
Caller / user / runtime policy decides what is acceptable
        ↓
Wallet / runtime enforces that policy
        ↓
Circle/payment rail performs settlement
```

The responsibilities are separate:

- **Verification = OMNI**: independently evaluate source-attributed evidence and compare the actual x402 payment requirements with the preflight observation when the caller supplies both.
- **Policy = caller, user, or runtime**: define acceptable price, asset, network, provider, evidence, and risk conditions.
- **Enforcement = wallet or runtime**: allow, hold, request review, or deny execution according to caller policy.
- **Settlement = Circle/payment rail**: perform payment settlement after the caller's enforcement layer permits it.

OMNI does not authorize or execute a payment. Its assessment and recommendation remain advisory inputs for an external policy and enforcement layer.

## Users

- autonomous coding/tool agents before package installation
- procurement/research agents before a paid API call
- x402 buyers before authorizing an Agent Wallet payment
- CI and agent platforms that need a deterministic policy input

## Intelligence planes

### Supply chain
OSV + CISA KEV + npm registry metadata + OpenSSF Scorecard + optional licensed package IOC feeds.

### Service identity
Circle Discovery + constrained unpaid x402 probe + OMNI historical provider/schema observations + optional licensed URL/hostname IOC feeds.

### Payment configuration
OMNI history tracks `payTo`, network and price changes. Licensed wallet IOCs can produce direct high-severity signals. A wallet relationship is evidence, not proof that two providers share an operator.

## x402 endpoint accountability

An x402 endpoint is a source of claims and payment requirements, not an authority. A marketplace listing or earlier preflight is also evidence, not proof that the endpoint will return the same service or payment configuration at execution time.

When available, OMNI evaluates:

- Circle/service identity
- constrained unpaid endpoint behaviour
- payment requirements
- `payTo`
- network
- atomic price
- provider, schema, and payment drift
- endpoint and wallet threat intelligence
- evidence freshness

The execution-time consistency model is:

```text
OMNI preflight observation
        ↓
actual selected PaymentRequirements / HTTP 402 challenge
        ↓
consistency comparison
        ↓
match | re-preflight | insufficient context
```

Stale or mismatched payment configuration requires a fresh assessment before automatic payment. OMNI reports the consistency result; it does not block the transaction.

## Decision contract

Every assessment returns:
- `riskScore` (0–100 conservative decision-risk score)
- `recommendation` (`proceed`, `proceed_with_caution`, `manual_review`, `do_not_proceed`)
- `evidenceCoverage` (coverage, not statistical confidence)
- dimension scores
- structured `signals` with stable reason codes
- raw source-attributed evidence
- `sourceErrors`

No LLM decides the verdict. Thresholds are policy defaults and must be calibrated against labelled incidents before they are described as predictive probabilities.

## Purchase-policy boundary

OMNI does not decide whether a purchase is economically worthwhile for a specific user. The following remain external caller, user, or runtime policies:

- maximum price per request
- daily or session budget
- allowed asset and network
- provider allowlists
- expected utility versus cost
- subscription versus pay-per-use economics

OMNI provides trust and payment evidence that these policies may consume.

## Reference enforcement integration

An optional runtime or wallet adapter may consume OMNI output and enforce caller policy. This is outside authoritative `RiskEngine` semantics.

For example, a caller may allow `AUTO-PAY` only when all of these are true:

- the preflight is fresh;
- actual selected payment requirements match the preflight;
- OMNI's recommendation satisfies the caller's threshold;
- `evidenceCoverage` meets the caller's minimum;
- the network and asset are allowed;
- the actual amount is within the caller's spending limits.

In this example, `manual_review` and `do_not_proceed` do not auto-pay. The wallet or runtime enforces this local policy; OMNI does not.

## Explicit non-goals for v0.3

- declaring a legal entity a scam based only on heuristics
- executing arbitrary third-party POST/PUT/DELETE endpoints during preflight
- malware sandboxing of package tarballs
- attribution of wallet ownership
- redistributing third-party threat-feed data without contractual rights
- wallet custody or buyer private-key management
- arbitrary third-party payment execution
- settlement authorization
- replacing caller-defined spending policy
- determining user-specific economic utility

## Success criteria before v1.0

1. Real Circle testnet paid E2E across every paid route.
2. At least one licensed commercial threat-intelligence source in production.
3. Historical x402 drift tested against known provider changes.
4. False-positive/false-negative evaluation set for risk reason codes.
5. Durable post-payment result/idempotency behavior is verified against the PostgreSQL-backed recovery path.
6. p95/p99 and saturation metrics under measured load.
7. A real wallet/runtime integration demonstrates: discover endpoint → OMNI preflight → actual HTTP 402 challenge → consistency check → local policy enforcement → Circle payment or deterministic deny/re-preflight. The integration exercises a successful match/pay path, a mismatch/re-preflight path, and a deny/manual-review path.
