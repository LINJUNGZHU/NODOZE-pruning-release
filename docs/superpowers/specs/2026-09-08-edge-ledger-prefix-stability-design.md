# RDP-Guard Research Evidence and Prefix Stability Design

Date: 2026-09-08

## Objective

Upgrade RDP-Guard from a working pruning prototype to an auditable experimental implementation. The online method must use only provenance events, historical frequencies, and declared POIs. Ground truth remains an offline evaluator. Every candidate edge must have a durable score record, high-scoring edges must be directly inspectable, adding POIs must not rewrite evidence already produced by earlier POIs, and certificate failures must be explicit.

This work does not claim that publication at a CCF-A venue is guaranteed. It supplies the algorithmic invariants, artifacts, baselines, and reporting discipline needed for a defensible submission-quality evaluation.

## Method: PS-RDP-CPF

The upgraded method is called **PS-RDP-CPF**: Prefix-Stable Rarity-Diffusion Pruning with a Causal Path Forest.

For candidate edge `e`, historical rarity `R(e)` is computed before the earliest POI from node-type, relation, and `(source type, relation, destination type)` counts. For each POI `p`, time-respecting bidirectional diffusion produces `D(e,p)`. Optional path, dependency-impact, and behavior signals are bounded to `[0,1]`. The POI-local diffusion-gated score is:

```text
z(e,p) = D(e,p) * [wd + wr R(e) + wp P(e,p) + wi I(e,p) + wb B(e,p)]
```

Each `z(e,p)` is normalized inside one fixed candidate graph. POI-local scores are immutable. A prefix of `k` POIs is aggregated by noisy-OR:

```text
Z_k(e) = 1 - product(1 - z(e,p)), p=1..k
```

Therefore `Z_(k+1)(e) >= Z_k(e)` for every edge. This is an importance score, not an attack probability or calibrated confidence.

The CADETS prefix runner computes one immutable local score map per chronological POI over the same fixed investigation graph. This prevents a newly added POI from retraining a joint DEPIMPACT projection or behavior cluster assignment for older POIs. It also records the winning/local support provenance for every aggregate score.

The certificate topology is an explicit path cover declared before candidate search. Every POI occurs in exactly one ordered sequence. A single sequence is a chain; multiple sequences form a causal forest. Strict witness bridges are required only between adjacent POIs inside the same declared sequence. Candidate disconnection never creates a branch automatically: this prevents a search miss from being relabeled as a valid fork. For UBC-13, the report-aligned nginx-to-pEja chain and the report-confirmed sshd branch are declared separately because the DARPA report states that repeated sshd injection attempts failed.

## Bounded-churn selection

At prefix `k>1`, the prior retained set is an online input. Certificate edges for the current POI prefix are mandatory. The declared removal allowance is the sum of budget contraction, newly mandatory non-prior edges, and `ceil(rho * B)`, capped by the prior-set size. A bitset bounded-subset planner then reconstructs a feasible set of indivisible prior atomic groups. It uses deterministic IDs to break packing ties and current score density for subsequent positive-utility admission.

The report separates `declared_allowed_removed_previous_edges` from the exact additional `atomicity_churn_slack_edges` that is unavoidable under the current raw capacity. It also records the effective allowance, added/removed counts, Jaccard similarity, and constraint state. Atomic packing does not receive a blanket worst-case allowance. If the reconstructed selection still violates the effective bound (for example because extra connectivity structure makes it unattainable), the prefix is fail-closed as `churn_constraint_status=infeasible` and is not advanced or summarized as complete. Zero-score groups are not selected in PS-RDP mode, so a large arbitrary event-ID tie cannot masquerade as evidence.

## Complete edge-score ledger

Each experiment writes a sibling artifact directory. A POI-prefix result uses `scenario-NN/poi-prefix-k-ledger/`.

- `edge-scores.jsonl.gz`: exactly one row per candidate edge, ordered by descending score then edge ID.
- `candidate-graph.jsonl.gz`: every field of every candidate node and stored edge in canonical order.
- `high-anomaly-edges.json`: all edges meeting the declared high-score rule, not a top-N truncation.
- `manifest.json`: schema version, counts, thresholds, candidate digest, artifact SHA-256 hashes, configuration, score semantics, and completeness checks.

Each score row records stable edge identity, endpoints, relation, timestamp, host, normalized aggregate score, rank, empirical percentile, high-score flag, all fused components, historical rarity evidence, POI support count, and local winner provenance. It also records one decision per requested budget: kept/not kept plus all applicable reasons.

The writer streams the full ledger and high-score projection through temporary
files instead of retaining a second in-memory copy of all high-score rows. The
manifest records the exact key schema for score components, rarity evidence,
and noisy-OR provenance. The writer and verifier reject missing per-edge
evidence, nested NaN/Inf values, malformed support/winner provenance, or a
`keep_ratios` configuration whose canonical keys do not exactly match the
decision matrix.

The high-score rule is fixed and reproducible:

```text
effective_cutoff = max(absolute_threshold, positive_score_quantile)
high_score = score > 0 and score >= effective_cutoff
```

Defaults are absolute threshold `0.8` and positive-score quantile `0.99`. Ties at the cutoff are all retained. The ledger is deterministic gzip (`mtime=0`), written via temporary files and atomically renamed. The manifest is written last and contains SHA-256 hashes. The v2 verifier independently checks the full candidate identity, row/edge bijection, finite score range, rank/order, percentile, threshold and complete tie set, budget-decision coverage, and non-empty reasons for every kept edge. Every experiment invokes this verifier immediately after writing and fails closed before committing the prefix result.

## Selection explanations

Every kept edge receives one or more machine-readable reasons:

- `protected_alert`: mapped POI/alert edge;
- `seed_incident`: edge incident to a protected seed when that policy is enabled;
- `causal_path_cover`: edge is a declared POI or strict witness bridge;
- `ordered_stage_backbone`: v2 compatibility alias for a path-cover edge;
- `connectivity_target` or `connectivity_bridge`;
- `prior_retention`: retained for prefix stability;
- `positive_score_rank`: admitted by positive marginal utility;
- `atomic_group_expansion`: included with a merged dependency group.

An unkept edge has an empty reason list. The ledger joins scores and decisions by numeric edge ID and stable event ID.

## Strict certificate states

The online certificate reports a state rather than presenting all retained POIs as a complete attack-chain proof:

- `valid`: at least two ordered POIs exist, every candidate stage pair is connected, all POIs and witnesses are retained, and the certificate fits the budget;
- `valid_forest`: multiple predeclared causal paths exist, every within-path stage pair is strictly connected and retained, and all branches fit the budget;
- `poi_only`: one POI is retained and budget-feasible; no multi-stage path claim is made;
- `unordered_multi_poi`: multiple POIs were supplied without a declared order; no path claim is made;
- `candidate_disconnected`: at least one ordered pair is not connected in the candidate graph;
- `budget_infeasible`: the mandatory certificate exceeds the raw-event budget;
- `missing_poi`: a declared certificate POI is absent or not retained.

`path_certificate_valid` and `causal_path_cover_certificate_valid` are true for `valid`, `valid_forest`, and `poi_only`. `strict_multistage_certificate_valid` remains true only for a single `valid` chain with at least one stage pair. `certificate_topology`, `certificate_branch_count`, and `candidate_disconnected_stage_pairs` make the declared structure and any failure auditable. Every retained stage witness is persisted as `(start POI, target POI, bridge edge IDs)` and independently recomputed on the retained graph under strict lexicographic `(timestamp_ns, edge_id)` order. Candidate-disconnected and unordered multi-POI sets therefore cannot yield a positive path-cover certificate.

## Correct per-alert aggregation

When multiple independent POI scorers contribute to one edge, noisy-OR produces the aggregate. Components and provenance are updated only from the local scorer that actually provides the maximum local score. This fixes the previous mismatch where the aggregate score used a maximum but the component dictionary was blindly overwritten by the last alert group.

## Online/offline boundary

The scorer and selector accept no ground-truth object. All requested primary
budgets are scored and pruned before the evaluation layer dereferences a ground
truth object or performs a ground-truth event lookup. In the prefix sweep, the
fixed reference is supplied lazily: it is first constructed after prefix 1 has
finished online selection, then cached for later offline evaluation. This also
prevents reference-event queries from warming SQLite pages before measured
online work. Ground truth is never passed to candidate construction, scoring,
aggregation, pruning, certification, or ledger classification. The ledger
labels its score as `heuristic_importance`, never anomaly probability. The
prefix summary labels the hindsight-selected minimum POI count as offline
analysis and never as a deployment stopping rule.

## Evaluation protocol

The immediate regression experiment is the fixed 14-prefix CADETS E3 sweep at a 20% raw-event ceiling. UBC-13 changes two late C2 POIs to the first report-aligned C2 observables so that the declared nginx-to-pEja stage boundary precedes the payload write/execute bridge; this POI change is versioned in the manifest rather than hidden as a candidate-graph change. The sweep reports:

- compression and unused budget;
- complete derived-reference-path retention and derived event recall;
- certificate state and witness counts;
- consecutive-prefix Jaccard, added/removed edges, and churn-bound compliance;
- score monotonicity violations (required to be zero);
- complete-ledger row/identity/hash checks;
- runtime and peak-memory diagnostics.

Required paper-scale follow-up is documented separately: full graph, random, temporal, rarity-only, diffusion-only, legacy RDP-Guard, adapted NoDoze/DEPIMPACT, and PS-RDP baselines; factorial signal ablations; multiple DARPA corpora/scenarios; multiple stochastic seeds; paired confidence intervals and non-parametric comparisons; and independently reviewed paths where available.

## Acceptance criteria

1. Every candidate edge is present exactly once in the score ledger.
2. Every retained edge has a decision and at least one reason.
3. High-score index equals the complete set implied by the manifest cutoff.
4. Artifact hashes validate and no manifest is published after a failed partial write.
5. A prior POI's local score digest is identical in all later prefixes on the fixed graph.
6. Aggregate scores have zero prefix-monotonicity violations.
7. Candidate-disconnected multi-stage sequences are not reported as valid certificates.
8. Feasible runs do not exceed the raw-event budget.
9. Declared, atomicity, and effective churn bounds are explicitly reported, and a violated bound fails the prefix closed.
10. Existing ingestion, search, scoring, and evaluation tests continue to pass.
11. Ground-truth providers and event lookups occur only after all primary
    pruning decisions are frozen.
12. Evidence schemas, finite nested values, noisy-OR winner/support semantics,
    and configured decision budgets survive independent deep verification.
13. Every POI appears exactly once in the online path cover; input, report, and
    ledger topology agree byte-for-byte at the event-sequence level.
14. A completed sweep passes the independent v3 validator; the launcher writes
    `validation_status=passed` only after that validator exits successfully.
