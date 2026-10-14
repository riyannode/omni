# ERC-8004 Reputation Research

## Decision

Production reputation scoring remains **disabled**:

```json
{"trustedReviewers": [], "recognizedTags": []}
```

The ReputationRegistry is treated as raw public evidence. No observed reviewer/tag pair met OMNI's production provenance standard: an exact reviewer address, a verifiable operator/entity, a public source proving that ownership, and documented tag/value semantics suitable for deterministic security scoring.

## Official sources

- ERC-8004 specification: https://eips.ethereum.org/EIPS/eip-8004
- Official implementation and deployment list: https://github.com/erc-8004/erc-8004-contracts
- Official deployment README: https://raw.githubusercontent.com/erc-8004/erc-8004-contracts/main/README.md

The specification defines `NewFeedback(uint256,address,uint64,int128,uint8,string,string,string,string,string,bytes32)`, signed `int128` values, `valueDecimals` from 0 through 18, optional tags, and revocation. It explicitly leaves aggregation and reviewer filtering to off-chain systems and warns about Sybil/spam risk. It does not define a universal meaning for arbitrary tags.

Official production registry addresses inspected:

| Chain | IdentityRegistry | ReputationRegistry | Source |
|---|---|---|---|
| Ethereum Mainnet (`eip155:1`) | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` | `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` | official contracts README |
| Base Mainnet (`eip155:8453`) | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` | `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` | official contracts README |

## Read-only chain observations

The observations used public JSON-RPC `eth_blockNumber` and `eth_getLogs` only. No transaction, signing, payment, or contract write was performed.

### Ethereum Mainnet

- Latest block observed: `26021097`.
- Bounded window: blocks `26011098..26021097` (10,000 blocks).
- `NewFeedback`: 147 events.
- `FeedbackRevoked`: 0 events.
- Decoded events: 147; decode failures: 0.
- Unique reviewer addresses: 2.
- Reviewers observed: `0xb6d0a187b050fa5bb0b87033a203f37becf4a775` (146), `0xe6906a58ea17e28afefba5bbcd5eba85bf58a122` (1).
- Tags observed: `verification:structural` (140), `verification:checks` (4), `review:submission` (2), `audit` (1).
- All 147 observed entries used `valueDecimals=0`.
- Sample values included `verification:structural=1` with `tag2=acceptance-v2`, and `audit=95` with `tag2=dev`.

A 50,000-block query was rejected by the public RPC as an archive request requiring a personal token, so the Ethereum result is explicitly a bounded recent-window sample, not a full-history total.

### Base Mainnet

- Latest block observed: `51573271`.
- Bounded window: blocks `51553272..51573271` (20,000 blocks), queried in 1,999-block chunks because the public RPC limits `eth_getLogs` ranges.
- `NewFeedback`: 1,439 events.
- `FeedbackRevoked`: 0 events.
- Decoded events: 1,439; decode failures: 0.
- Unique reviewer addresses: 8.
- Dominant reviewers: `0x7cf8286c9b476de7c262d086e2861fecefd3810b` (730), `0xd834a7624767dafbbe9831df22914e805924e2a6` (663), `0x8e07bc402d6840021e5ebfd6174b2ed49055f432` (30), `0x6b51d0d67ff41dab76e499546abe6b8b03cf8732` (8), `0xec1ccf31c61ef3177573c0db9398a0ec4d0c356b` (5); three other addresses occurred once each.
- Tags observed: `miner-vouch` (1,401), `starred` (32), and one each of `tmp.task.requester`, `orchestration`, `analytics`, `security`, `payments`, and `automation`.
- All 1,439 observed entries used `valueDecimals=0` and the recent sample was predominantly `value=1`.

A public BaseScan transaction for `0x7cf8286c9b476de7c262d086e2861fecefd3810b` shows `giveFeedback` with agent `25975`, `value=1`, `valueDecimals=0`, `tag1=miner-vouch`, `tag2=botcoin`, endpoint `https://coordinator.agentmoney.net`, and a feedback URI under that domain:

- https://basescan.org/tx/0x9b0b777359c1f6e0a330763ba6cf250935aa8872cbe3d670c21338b483a0333d

This is useful evidence of observed payload semantics for that transaction, but it does not prove a legal entity owns the reviewer address or that `miner-vouch` is a stable security signal.

## Reviewer and tag policy assessment

| Reviewer | Chain | Public provenance | Tag/value observation | Production decision |
|---|---|---|---|---|
| `0xb6d0a187b050fa5bb0b87033a203f37becf4a775` | Ethereum | No independently verifiable operator/entity source found | `verification:structural`, `verification:checks`, `review:submission`; decimals 0 | Not trusted |
| `0xe6906a58ea17e28afefba5bbcd5eba85bf58a122` | Ethereum | No independently verifiable operator/entity source found | one `audit=95`, decimals 0 | Not trusted |
| `0x7cf8286c9b476de7c262d086e2861fecefd3810b` | Base | BaseScan exposes an AgentMoney coordinator URL in one feedback transaction, but no public ownership proof for the address | `miner-vouch=1`, decimals 0, `tag2=botcoin` in sampled transaction | Not trusted |
| `0xd834a7624767dafbbe9831df22914e805924e2a6` | Base | No independently verifiable operator/entity source found | `miner-vouch=1`, decimals 0 in sampled entries | Not trusted |
| other observed Base reviewers | Base | No independently verifiable operator/entity source found | Low-frequency mixed tags, decimals 0 | Not trusted |

The EIP's illustrative `starred` example describes a 0–100 quality rating, but that normative example does not prove that any observed address is an authoritative `starred` reviewer or that the tag is appropriate for OMNI security scoring. Accordingly, no observed tag is added to `recognizedTags`.

OMNI continues to preserve all bounded observations, revoked filtering, recognized-tag counting, reviewer filtering, decimal validation, history coverage, and score-eligible counts. A feedback entry affects risk only when every configured policy condition passes. No feedback-count, reviewer-frequency, reviewer-age, balance, or popularity heuristic is used as trust.
