# OMNI PRD — v0.2

## Product thesis

Autonomous agents increasingly install third-party software, call paid services, and authorize machine payments. Existing controls are fragmented: vulnerability databases answer software questions, marketplace discovery answers listing questions, and wallet policies bound spend, but the agent still lacks one machine-consumable pre-execution risk decision layer.

OMNI answers one question before a consequential action: **what evidence says this install/call/payment deserves caution right now?**

## Users

- autonomous coding/tool agents before package installation
- procurement/research agents before a paid API call
- x402 buyers before authorizing an Agent Wallet payment
- CI and agent platforms that need a deterministic policy input

## v0.2 intelligence planes

### Supply chain
OSV + CISA KEV + npm registry metadata + OpenSSF Scorecard + optional licensed package IOC feeds.

### Service identity
Circle Discovery + constrained unpaid x402 probe + OMNI historical provider/schema observations + optional licensed URL/hostname IOC feeds.

### Payment configuration
OMNI history tracks `payTo`, network and price changes. Licensed wallet IOCs can produce direct high-severity signals. A wallet relationship is evidence, not proof that two providers share an operator.

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

## Explicit non-goals for v0.2

- declaring a legal entity a scam based only on heuristics
- executing arbitrary third-party POST/PUT/DELETE endpoints during preflight
- malware sandboxing of package tarballs
- attribution of wallet ownership
- redistributing third-party threat-feed data without contractual rights

## Success criteria before v1.0

1. Real Circle testnet paid E2E across every paid route.
2. At least one licensed commercial threat-intelligence source in production.
3. Historical x402 drift tested against known provider changes.
4. False-positive/false-negative evaluation set for risk reason codes.
5. Durable post-payment result/idempotency design.
6. p95/p99 and saturation metrics under measured load.
