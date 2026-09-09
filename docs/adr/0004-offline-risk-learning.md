# ADR 0004 — Offline risk learning and calibration

Status: accepted.

## Decision

OMNI is learning-ready, not self-learning. Production runtime verdicts remain deterministic and reproducible. The production policy never self-modifies, and it is never loaded remotely or from request/user input.

The long-term operating invariant is:

```text
adaptive during policy development,
deterministic during execution
```

Production decisions must remain deterministic, reproducible, versioned, source-attributed, auditable, reversible, and human-approved. The same evidence plus the same production policy/model version must produce the same authoritative result.

Evidence acquisition is separate from deterministic feature extraction. Feature extraction is pure and versioned; scoring is deterministic and uses an explicit versioned `RiskPolicy`. Historical assessments retain the snapshot, features, assessment, and schema versions so decisions remain replayable across policy changes.

Ground-truth labels are independent outcome information with explicit provenance (for example, a confirmed incident report, security advisory, operator-verified investigation, postmortem, or independently validated benign outcome). Labels are not inferred from risk scores, recommendations, signals, threat matches, or listing state.

Learning and calibration happen offline. Candidate policies and models must be strictly validated and replay-tested against labelled historical data. A future statistical or ML model may run in shadow mode on the same features, but shadow output is observation-only and cannot change production recommendations. Promotion to an authoritative policy/model must be explicit, manually controlled, versioned, reversible, and benchmarked. No ML/LLM may silently become payment authorization authority.

Thompson-sampling/bandit-style online reward updates are inappropriate for OMNI's authoritative verdict: unlike an online adaptive buyer, OMNI does not receive immediate, reliable post-action ground truth. Risk outcomes are delayed and may require independently verified incident labels.

## Current foundation

OMNI currently provides offline evaluation and policy replay, not automatic statistical learning:

1. **Assessment journal** stores the normalized snapshot, extracted deterministic features, assessment result, policy version, snapshot schema version, feature schema version, and assessment timestamp.
2. **Independent labels** currently use the shape `benign | incident`. Label provenance includes `source`, optional `sourceReference`, optional `notes`, and `labeledAt`.
3. **Deterministic versioned feature extraction** produces facts from normalized evidence.
4. **Candidate `RiskPolicy` replay** evaluates labelled historical assessments against an isolated candidate policy.
5. **Historical cohort compatibility checks** keep unsupported schema cohorts out of replay.
6. **Feature-drift detection** distinguishes schema evolution from actual semantic drift where the cohort contract permits it.
7. **Offline evaluation metrics** include TP, FP, TN, FN, precision, recall, false-positive rate, false-negative rate, false-negative count, and the confusion matrix represented by those counts.
8. **Manual candidate-policy promotion** is the boundary between offline evaluation and any future production change.

The current small live repository acceptance set is functional validation evidence only. It is not sufficient statistical training evidence.

## Future target architecture

The future pipeline is:

```text
Production assessment
        |
        v
AssessmentJournal
        |
        v
independently labelled historical data
        |
        v
schema/cohort compatibility filter
        |
        v
deterministic feature dataset
        |
        v
offline trainer
        |
        v
candidate model / candidate policy artifact
        |
        v
offline evaluator
        |
        v
shadow mode
        |
        v
manual promotion gate
        |
        v
versioned deterministic production policy/model
```

The authoritative runtime never trains itself. A production assessment may append evidence and journal data, but it does not update coefficients, weights, thresholds, labels, or policy state in the request path.

## Phase 1 — Dataset foundation

The first implementation should establish a deterministic training-dataset builder over labelled `AssessmentJournal` rows.

Requirements:

- only compatible historical cohorts are eligible;
- incompatible repository schemas fail closed;
- feature drift excludes rows from training unless explicitly reconciled;
- labels remain independent of OMNI's own score and recommendation;
- label provenance is preserved;
- assessment timestamp is preserved;
- subject type is preserved;
- policy and snapshot/feature schema versions are preserved;
- input rows and generated rows have deterministic ordering;
- the dataset-builder version is explicit and reproducible.

The same journal state plus the same dataset-builder version must produce the same training rows and ordering. Dataset generation must not depend on wall-clock time, network ordering, mutable provider responses, or process-local iteration order.

Future label vocabulary may include:

- `benign`
- `malicious_package`
- `known_exploitation`
- `supply_chain_incident`
- `compromised_workflow`
- `provenance_mismatch_confirmed`
- `credential_exposure`
- `false_positive`

These are future work. Do not change the current production label schema merely for this roadmap.

## Phase 2 — Baseline learner

The recommended first statistical model is **monotonic logistic regression**.

Reasons:

- deterministic inference;
- interpretable coefficients;
- suitable for small datasets;
- auditable output;
- straightforward versioning;
- lower overfitting risk than complex models;
- compatibility with risk-direction constraints.

The model consumes deterministic facts, never raw prose. Candidate features may eventually include:

- Scorecard-derived practice risk as source facts, not only the current policy score;
- lifecycle-script presence;
- mutable GitHub Action refs;
- workflow write permissions;
- download/execute findings;
- verified provenance source mismatch;
- verified provenance commit mismatch;
- vulnerability counts by severity;
- known-exploited count;
- MAL-* observation count;
- threat-intelligence counts by severity;
- exact dependency count;
- unresolved dependency ratio;
- evidence coverage;
- inspected security-file count.

Do not encode current policy scores as training features when doing so would create label leakage or merely teach the learner to reproduce existing weights. Prefer source facts and version the feature contract.

## Monotonicity contract

Risk-positive facts must not be learned with a direction that lowers predicted risk. Monotonic constraints are part of the model contract, not merely a training preference.

Examples:

- more critical vulnerabilities must not reduce predicted risk;
- KEV-positive evidence must not reduce predicted risk;
- active MAL-* evidence must not reduce predicted risk;
- strong verified provenance mismatch must not reduce predicted risk;
- more independent high-risk evidence must not reduce predicted risk solely because it is repeated across sources.

Constraint validation belongs in candidate-model evaluation. A candidate that violates a required direction is not promotable even if aggregate metrics improve.

## Phase 3 — Interaction features

After a simple baseline is understood, future work may add explicit deterministic interaction features, such as:

- mutable Action ref + workflow write permission;
- mutable Action ref + download/execute;
- provenance mismatch + high/critical vulnerability;
- critical vulnerability + KEV;
- multiple independent high-risk evidence sources.

Interactions must be deterministic, bounded, documented, and versioned. Their semantics must be defined by OMNI policy development rather than invented dynamically by the learner. Every interaction must have a reproducible extractor and an evaluation case.

## Phase 4 — Calibration

After the baseline model has stable held-out behavior, optional probability calibration may be added. The recommended initial calibrator is **isotonic regression** because it can improve empirical probability calibration without requiring a complex model family.

A future candidate probability of `0.80` should mean that similarly scored historical cases have an approximately comparable incident rate, subject to dataset quality, sampling, label quality, and the selected evaluation cohort.

Current OMNI `riskScore` is not a statistical probability. It remains an integer policy-risk score in `0..100`. A calibrated probability, if introduced, is a separate versioned output with separate semantics and must not silently replace `riskScore`.

## Phase 5 — Shadow mode

Future runtime modes are conceptual only in this ADR:

1. **`DETERMINISTIC`**
   - current authoritative production policy only;
   - no candidate model participates in the decision.

2. **`SHADOW_CALIBRATED`**
   - the current production result remains authoritative;
   - a candidate model runs separately on the same accepted features;
   - candidate output is recorded only for comparison;
   - disagreement, latency, errors, and feature-version mismatch are observable.

3. **`CALIBRATED_APPROVED`**
   - a manually promoted, versioned calibrated model/policy may participate in authoritative scoring under explicit policy rules;
   - the promoted artifact remains immutable and rollbackable.

Shadow output must never:

- modify the production recommendation;
- authorize payment;
- mutate `RiskPolicy`;
- feed itself back as a training label;
- write new authoritative weights;
- silently change a hard safety result.

A future shadow observation could look like:

```text
authoritativeRiskScore: 35
shadowRiskScore: 18
authoritativeRecommendation: proceed_with_caution
shadowProbability: 0.12
```

An independent later label such as `benign` is outcome data. The shadow result is not the label.

## Phase 6 — Hard safety invariants

Statistical calibration may not override explicit hard safety facts unless a future separately reviewed policy explicitly changes the invariant.

Initial hard-safety examples include:

- an active exact-version MAL-* observation;
- explicit CISA KEV-positive evidence;
- other future conditions explicitly designated by a reviewed policy.

A learned model returning a lower probability must not silently suppress an authoritative hard safety condition:

```text
MAL observed
 deterministic hard condition = do_not_proceed
 shadow model probability = 0.42
 authoritative result remains do_not_proceed
```

Hard-safety misses must be reported as a first-class evaluation failure, not hidden inside aggregate accuracy or calibration metrics.

## Phase 7 — Train / validate / test

Future learner evaluation must not train and evaluate on the exact same data.

When enough data exists, prefer a deterministic temporal split:

```text
train:      older labelled assessments
validation: later labelled assessments
test:       latest held-out labelled assessments
```

Temporal separation reflects changes in evidence providers, ecosystems, attack patterns, and repository behavior. The exact split policy, cutoff rules, cohort filters, and random-seed policy must be versioned.

Prevent subject leakage. Repeated assessments of the same repository, package, or endpoint must not appear across train and test in a way that artificially inflates performance. Where subject-grouped splitting is required, the grouping rule must be deterministic and recorded in the dataset metadata.

## Phase 8 — Evaluation gates

Future candidate models and policies should report at minimum:

- dataset size;
- benign count;
- incident count;
- subject distribution;
- schema distribution;
- precision;
- recall;
- false-positive rate;
- false-negative rate;
- false-negative count;
- confusion matrix;
- calibration error;
- hard-safety misses;
- feature drift;
- candidate-versus-authoritative disagreement rate;
- evaluation split and dataset-builder versions.

Accuracy alone is not promotion evidence. Security promotion must make false negatives and hard-safety misses explicitly visible. A candidate that improves average metrics while creating unacceptable hard-safety misses is rejected.

Promotion should depend on enough independently labelled examples, representation of important risk classes, held-out evaluation quality, stable calibration, acceptable false-negative behavior, and zero unexplained hard-safety misses. Do not invent an arbitrary fixed minimum such as exactly 100 or 1000 rows; data sufficiency is a quality and representation decision.

## Phase 9 — Versioned model artifact

A future immutable candidate artifact may carry conceptual metadata such as:

```text
modelType:
monotonic_logistic_regression

modelVersion:
omni-calibration-v1

featureSchemaVersion:
N

datasetBuilderVersion:
N

trainingDatasetDigest:
sha256:...

trainedAt:
...

coefficients:
...

intercept:
...

monotonicConstraints:
...

calibration:
...

metrics:
...
```

This is documentation only and is not a final production file format. The eventual artifact must be immutable, content-addressable or digestable, reviewable, reproducible where practical, and explicitly promoted. The artifact must identify its feature schema, dataset builder, data digest, model version, calibration method, constraints, and evaluation results.

## Phase 10 — Policy export and promotion

Two future promotion paths remain open:

A. Keep the learned candidate as a deterministic model artifact used by the `RiskEngine` under an explicitly versioned model contract.

B. Convert learned coefficients/results into a conventional versioned `RiskPolicy` after human review.

Do not decide this permanently in this docs-only change. The initial implementation should prefer whichever path preserves explainability, deterministic execution, easy rollback, and policy auditability.

Every promotion must be human-controlled, recorded, reversible, and associated with an immutable artifact digest. No stage automatically promotes itself, and no automatic rollback may occur solely because a model metric changed.

## Phase 11 — More complex models

After sufficient labelled data and a proven baseline, OMNI may evaluate monotonic gradient-boosted trees, such as LightGBM or XGBoost configurations with monotonic constraints.

This is not the initial implementation recommendation. It is optional future progression only after:

- the dataset contract is stable;
- temporal and subject-leakage controls are proven;
- the logistic baseline is understood;
- hard-safety tests are comprehensive;
- held-out performance and calibration justify the added complexity;
- the more complex artifact remains deterministic, inspectable, versioned, and reversible.

Neural networks are not recommended as the initial authoritative scorer. LLM-based authoritative scoring, reinforcement learning, Thompson sampling, and online bandit reward updates are also currently inappropriate because OMNI lacks immediate, reliable post-action ground truth and authoritative decisions must remain reproducible.

## Uncertainty remains separate

The repository-risk architecture preserves:

```text
Observed Risk
Evidence Coverage
Model Calibration
Recommendation Gate
```

These concepts are related but not identical.

Future statistical learning must not automatically reinterpret any of the following as malicious evidence:

- provider failure;
- unavailable source;
- unsupported format;
- unresolved dependency;
- deferred enrichment;
- incomplete collection.

A model may eventually use evidence completeness as a predictive feature for calibration or review routing, but missing evidence must not become a fabricated security finding. Coverage and score status remain explicit uncertainty signals, and recommendation gating remains a policy decision.

## Implementation order

The concrete future implementation order is:

- **Stage A:** deterministic dataset builder and richer evaluator;
- **Stage B:** monotonic logistic-regression trainer;
- **Stage C:** candidate artifact with reproducibility metadata;
- **Stage D:** shadow scoring storage and disagreement reports;
- **Stage E:** probability calibration;
- **Stage F:** human-controlled promotion mechanism;
- **Stage G:** optional monotonic GBDT after sufficient data.

No stage automatically promotes itself. Each stage must preserve the deterministic execution contract and pass the applicable evaluation gates before the next stage begins.

## Data sufficiency and labels

The current small live repository acceptance set is useful for functional validation of evidence acquisition and deterministic scoring. It is not sufficient statistical training evidence.

Promotion requires a dataset with enough independently labelled examples and meaningful representation of important risk classes. The decision must consider held-out evaluation quality, stable calibration, acceptable false negatives, and absence of hard-safety misses. Data sufficiency is not established by code existence, row count alone, or a single live acceptance run.

## Non-goals

This roadmap does not authorize or implement:

- a self-modifying production `RiskPolicy`;
- per-request online training;
- LLM authoritative risk decisions;
- automatic payment authorization from ML output;
- labels derived from OMNI's own recommendation;
- training on unversioned features;
- silent model promotion;
- automatic rollback based solely on model metrics;
- any claim that calibrated probability equals certainty;
- autonomous reinforcement learning, Thompson sampling, or online bandit reward updates.

## Relation to PR #28

PR #28 establishes the repository-risk evidence and deterministic scoring foundation on which future calibration can operate. It provides versioned repository features, repository vulnerability and threat-intelligence summaries that survive bounded detail reduction, deterministic scoring, evidence-uncertainty separation, candidate policy replay, and historical cohort compatibility checks.

PR #28 itself does not implement:

- statistical model training;
- adaptive production weights;
- shadow-model runtime;
- automatic policy generation;
- probability calibration;
- online learning;
- automatic promotion.

This ADR update is roadmap and design documentation only. It does not change runtime behavior, scoring, schemas, tests, policy weights, deployment configuration, or payment behavior.
