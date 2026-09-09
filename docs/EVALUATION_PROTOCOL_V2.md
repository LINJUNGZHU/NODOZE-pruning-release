# Evaluation Protocol v2

Version: `tc-pruning-evaluation-v2.0`

This protocol evaluates a fixed candidate graph and its retained subgraphs. It does not change POIs, causal search, scoring, pruning, or reference annotations.

## Reference annotation classes

1. Human-reviewed node labels are entity UUIDs published by UBC/ORTHRUS. Their source path and SHA-256 are recorded.
2. Rule-derived event labels are database events whose source and destination are both labeled nodes and whose timestamp is inside the fixed scenario window. They are not official event-wise ground truth.
3. Derived reference paths are automatically constructed exact event sequences. They are not human-verified attack paths. Human-verified path metrics remain N/A until an independently reviewed path manifest is supplied.

Each class records `source`, `version_or_hash`, `scope`, `generation_rule`, and `verification_status`. Automated checks never promote an item to `human_verified`.

## Graph size and compression

Events are deduplicated by exact `event_id`. Nodes are stable entity UUID endpoints; isolated nodes are excluded. Process names are never used as node identity. Parallel event groups preserve the exact member event IDs.

`actual_event_retention = retained_event_count / candidate_event_count`

`event_compression = 1 - actual_event_retention`

`node_compression = 1 - retained_node_count / candidate_node_count`

Candidate extraction from the source database is scope reduction, not pruning compression. Byte compression is reported only when candidate and output graphs are serialized with identical format and encoding.

## Recall metrics

For candidate graph C, retained graph S, node labels T_V, and derived event labels T_E:

- `candidate_node_recall = |V_C intersect T_V| / |T_V|`
- `final_node_recall = |V_S intersect T_V| / |T_V|`
- `candidate_derived_event_recall = |E_C intersect T_E| / |T_E|`
- `final_derived_event_recall = |E_S intersect T_E| / |T_E|`
- `conditional_derived_event_retention = |E_S intersect T_E| / |E_C intersect T_E|`

Every metric stores numerator, denominator, and value. A zero denominator produces null with a reason. Scenario metrics deduplicate event IDs. Per-POI macro and micro results require each POI's candidate identity set; they are N/A for older files that omitted those sets.

Precision, FPR, and F1 are omitted because unlabelled context is not an exhaustive negative class.

## Paths and reachability

Strict path retention requires every fixed event ID, nondecreasing timestamps, and directed endpoint continuity. An alternative reachable path does not satisfy an exact reference path. Candidate coverage, final retention, and retention conditional on candidate coverage are separate metrics.

`derived_reference_path_retention` applies only to automatically derived paths. `verified_attack_path_retention` applies only to independently human-reviewed paths. Entry-to-POI reachability is auxiliary and is never substituted for path retention.

## PS-RDP-CPF online certificate

The online path certificate is independent of reference annotations. Before candidate search, the POI input declares a disjoint cover of one or more ordered event sequences. All present POI events and the minimum-cost time-respecting bridges between consecutive stages inside each sequence form the mandatory certificate. Separate sequences are separate branches and are never joined by an invented cross-branch edge. The planner scans the relation-aware timestamp DAG and retains immutable predecessor states, so a later arrival cannot corrupt an earlier valid witness.

The certificate states include `valid` for one chain, `valid_forest` for multiple predeclared paths, `poi_only`, `unordered_multi_poi`, `candidate_disconnected`, `budget_infeasible`, and `missing_poi`. `path_certificate_valid` and `causal_path_cover_certificate_valid` are true only for `valid`, `valid_forest`, and the single-anchor `poi_only` state. `strict_multistage_certificate_valid` is true only for `valid`. Every witness is persisted as start/target POI IDs plus bridge edge IDs and is recomputed on the retained graph under strict lexicographic `(timestamp_ns, edge_id)` order. A disconnected pair within a declared path or an unordered multi-POI set never produces a valid certificate, and a single retained POI is never described as a certified multi-stage attack chain.

`score_mass_retained = sum(score(e) for retained e) / sum(score(e) for candidate e)` is also an online metric. The recommended operating point is the smallest budget with a valid causal path-cover certificate, a feasible raw-event budget, a satisfied churn constraint, and score mass at or above `score_mass_target`; Ground Truth recall and path retention are prohibited inputs to this recommendation. Reference paths are evaluated only after pruning and remain the independent empirical test of attack-chain preservation beyond the declared POI stages.

`score_mass_retained` is a legacy field name for retained heuristic utility. It is neither calibrated confidence nor malicious-event probability.

## Complete edge evidence

Every new experiment writes a deterministic score ledger with exactly one record per candidate edge. Each record contains the aggregate score, all available components, raw historical frequency evidence, POI-score provenance, rank, percentile, high-score classification, and keep decisions with reasons for every tested raw-event budget. The high-score set is defined as all positive scores at or above the maximum of a fixed absolute threshold and a declared positive-score quantile; ties are included.

The v2 artifact also contains `candidate-graph.jsonl.gz`, a canonical serialization of every `NodeRecord` and `StoredEdge` field. All artifacts are SHA-256 hashed in a manifest written last. A run is complete only when deep verification recomputes the candidate identity, score range/order/ranks, high-score threshold and complete tie set, every per-budget decision, non-empty reasons for every retained edge, the per-edge evidence key schemas, finite nested evidence values, noisy-OR winner/support provenance, and the exact correspondence between configured keep ratios and decision keys. `python -m tc_pruning.cli verify-score-ledger --ledger PATH` performs this check, and the experiment invokes it automatically before committing a prefix.

All primary online pruning outputs are frozen before ground-truth annotations are dereferenced or ground-truth event IDs are queried. The POI-prefix runner constructs its fixed report reference through a lazy provider after the first online selection and caches it thereafter. This prevents both label leakage and ground-truth-dependent SQLite page-cache warming from contaminating the measured online phase.

For prefix experiments, POI-local score maps are immutable and identified by SHA-256; the accumulator is also bound to a digest of the complete graph, rarity/path maps, and score-affecting parameters. Prefix scores use a numerically stable noisy-OR update, so aggregate importance is monotonically nondecreasing edge by edge. Consecutive runs report local-digest violations, aggregate monotonicity violations, Jaccard similarity, additions, removals, the declared removal allowance, exact atomic-packing slack, effective allowance, and compliance. A violation is fail-closed.

The v3 sweep validator reads the online input rather than trusting the result's topology counters. It requires empty online attack labels, reconstructs the disjoint POI sequences, binds them to the report and ledger context, independently recomputes strict reachability on both the complete candidate graph and the retained graph, validates every witness edge and selection reason, and checks that path membership is prefix-stable. The detached launcher treats validation failure as process failure.

## Timing and memory

New experiments record end-to-end time, per-phase time including ledger writing and verification, baseline RSS, sampled peak RSS, peak increment, and per-method/per-budget pruning time. The RSS sampler is exception-safe and is always stopped when an experiment returns or raises. Older preserved files that lack these fields remain explicitly N/A.

## Relation to prior research

The protocol borrows evaluation ideas rather than claiming a universal conference standard: NoDoze motivates concise dependency graphs while retaining investigation context; DEPIMPACT evaluates reduced critical components and attack sequences; ORTHRUS emphasizes transparent, manually reviewed entity labels and attribution quality. The field names in this project are project-specific operational definitions.

## Legacy mapping

- `attack_event_recall` becomes `final_derived_event_recall` and gains numerator, denominator, and label type.
- `complete_path_retention` becomes `derived_reference_path_retention`; it was not verified-path retention.
- `single_run_latency_seconds` becomes `whole_experiment_seconds` for preserved files.
- `critical_relation_strict_recovery` remains a legacy diagnostic unless a fixed relation manifest is supplied.
