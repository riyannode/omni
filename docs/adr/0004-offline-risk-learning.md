# ADR 0004 — Offline risk learning and calibration

Status: accepted.

OMNI is learning-ready, not self-learning. Production runtime verdicts remain deterministic and reproducible. The production policy never self-modifies, and it is never loaded remotely or from request/user input.

Evidence acquisition is separate from deterministic feature extraction. Feature extraction is pure and versioned; scoring is deterministic and uses an explicit versioned `RiskPolicy`. Historical assessments retain the snapshot, features, assessment, and schema versions so decisions remain replayable across policy changes.

Ground-truth labels are independent outcome information with explicit provenance (for example, a confirmed incident report, security advisory, operator-verified investigation, postmortem, or independently validated benign outcome). Labels are not inferred from risk scores, recommendations, signals, threat matches, or listing state.

Learning/calibration happens offline. Candidate policies must be strictly validated and replay-tested against labelled historical data. A future statistical or ML model may run in shadow mode on the same features, but shadow output is observation-only and cannot change production recommendations. Promotion to an authoritative policy/model must be explicit, manually controlled, versioned, reversible, and benchmarked. No ML/LLM may silently become payment authorization authority.

Thompson-sampling/bandit-style online reward updates are inappropriate for OMNI's authoritative verdict: unlike an online adaptive buyer, OMNI does not receive immediate, reliable post-action ground truth. Risk outcomes are delayed and may require independently verified incident labels.
