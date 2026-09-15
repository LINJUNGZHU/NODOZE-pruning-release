# A_rasp Cross-Domain Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement and evaluate an opt-in reverse/forward reconstruction and reachability-aware branch-fair evidence selector on CADETS E3.

**Architecture:** Keep immutable raw evidence in `G_full`, derive a weighted `G_prop`, reconstruct roots/spheres/motifs, preserve verified temporal demand paths, and spend only the residual baseline-derived event budget with lazy branch-fair selection. Ground truth enters only a separate post-freeze analyzer/evaluator.

**Tech Stack:** Python 3.12, dataclasses, SQLite, NumPy, pytest, existing A_rasp and strict CADETS semantics.

**Spec:** `docs/superpowers/specs/2026-09-15-a-rasp-cross-domain-phase2-design.md`

## Global Constraints

- Default A_rasp and Phase 1 artifacts remain unchanged.
- Online code cannot import or read ORTHRUS/PDF/taxonomy data.
- Every graph element references real raw event IDs; unique raw IDs define cost.
- Strictly increasing event time and the existing semantics registry are mandatory.
- New parameters are config-driven and serialized in the online manifest.
- No fixed-depth/cap/session expansion is treated as the main Phase 2 method.

---

### Task 1: Offline miss taxonomy

**Files:** Create `tc_pruning/offline_analysis/candidate_miss.py`, `scripts/analyze_candidate_misses.py`, and `tests/test_candidate_miss_analyzer.py` (the repository already has `tc_pruning/evaluation.py`, so a same-name package is invalid).

**Interfaces:** `CandidateMissAnalyzer(store, registry).analyze(node_id, anchors, cutoff_ns) -> CandidateMissRecord`; JSON/Markdown serializers consume frozen V4 output plus evaluator-only GT.

- [ ] Write toy tests proving backward, forward, mixed, equal-time rejection, unsupported relation, and multi-label taxonomy behavior.
- [ ] Run the tests and confirm failure because the analyzer API is absent.
- [ ] Implement bounded bidirectional temporal-state search over the full database and exact witness serialization.
- [ ] Run analyzer tests and verify the online package has no evaluation import.

### Task 2: Full and clean propagation views

**Files:** Create `tc_pruning/investigation/graph_views.py`, `tc_pruning/investigation/propagation.py`, and `tests/test_clean_propagation_view.py`.

**Interfaces:** `InvestigationGraphs(full, propagation)` and `CleanPropagationBuilder.build(edges, cutoff_ns, history_stats)`; weights expose relation, decay, frequency, and fanout factors.

- [ ] Write failing tests for evidence preservation, relation-channel normalization, pre-cutoff history, hub suppression, and no double temporal decay.
- [ ] Implement typed immutable full references and relation-specific normalized transitions.
- [ ] Add optional progressive weight reduction with rank-stability telemetry; never delete full edges.
- [ ] Run focused and A_rasp propagation regressions.

### Task 3: Temporal reverse reachability

**Files:** Create `tc_pruning/investigation/reverse_reachability.py` and `tests/test_reverse_reachability.py`.

**Interfaces:** `TemporalReverseReachability.run(graphs, anchors, config) -> ReverseReachabilityResult` containing sketches, roots, support distribution, seed, timing, and fallback status.

- [ ] Write failing root, equal-time, deterministic-seed, hub suppression, and disconnected-noise stability tests.
- [ ] Implement indexed strict reverse traversal, exhaustive mode, weighted sketches, memoized states, and early stopping.
- [ ] Implement cross-seed top-root stability measurement and deterministic fallback.
- [ ] Run focused tests and determinism checks.

### Task 4: Forward spheres and verification

**Files:** Create `tc_pruning/investigation/forward_sphere.py` and `tests/test_forward_causal_sphere.py`.

**Interfaces:** `ForwardCausalSphereBuilder.build(root, graphs, online_signals, config) -> ForwardSphere`; `harmonic_verification(backward, forward)`.

- [ ] Write failing sibling-descendant, false-sibling, verified-sibling, long-useful-chain, and hub-stop tests.
- [ ] Implement incremental strict successor frontiers and configured marginal-gain/resource stopping.
- [ ] Implement label-free forward support and harmonic verification.
- [ ] Run focused tests and candidate-cap safety tests.

### Task 5: Replayable temporal motifs

**Files:** Create `tc_pruning/investigation/motifs.py` and `tests/test_temporal_causal_motifs.py`.

**Interfaces:** `TemporalCausalMotifBuilder.build(graph, anchors, verified_branches) -> tuple[TemporalCausalMotif, ...]`.

- [ ] Write failing tests for all seven motif families, missing witnesses, reverse/equal time, and eight-event raw cost.
- [ ] Implement indexed local joins that return real ordered witness IDs and semantic validity.
- [ ] Implement relevance/verification geometric score with weak rarity modulation.
- [ ] Run focused tests and strict-verifier regressions.

### Task 6: Demand pairs and temporal reachability skeleton

**Files:** Create `tc_pruning/investigation/reachability.py` and `tests/test_temporal_reachability_preserver.py`.

**Interfaces:** `TemporalDemandPair`, `TemporalDemandBuilder`, and `TemporalReachabilityPreserver.preserve(full_graph, demands, edge_costs, budget)`.

- [ ] Write failing strict-time, redundant-edge deletion, all-demand preservation, and explicit-overflow tests.
- [ ] Implement cached temporal-state shortest paths, path union, and deterministic redundancy elimination.
- [ ] Record mandatory cost, preserved demands, reachability rate, and infeasibility without deleting witnesses.
- [ ] Run focused tests and path-evaluation regressions.

### Task 7: Evidence units and branch-fair lazy greedy

**Files:** Create `tc_pruning/investigation/evidence_units.py`, `tc_pruning/investigation/branch_fair_selector.py`, and `tests/test_branch_fair_selector.py`.

**Interfaces:** `EvidenceUnit`, `BranchFairObjective`, and `LazyGreedySelector.select(units, mandatory_event_ids, budget)`.

- [ ] Write failing ECDF scale, branch starvation, diminishing-return, overlap-cost, determinism, and legacy-mode tests.
- [ ] Implement query-local ECDF while retaining raw score, online branch IDs, concave coverage, verification, and redundancy terms.
- [ ] Implement lazy heap selection with stale marginal recomputation and complete per-unit ledger fields.
- [ ] Run focused tests and frozen A_rasp parity tests.

### Task 8: Configuration, orchestration, and isolation

**Files:** Create `tc_pruning/investigation/phase2.py`, `configs/a_rasp_cross_domain_phase2.json`, `scripts/run_a_rasp_cross_domain_phase2.py`, and `tests/test_phase2_runner.py`.

**Interfaces:** modes `legacy`, `reverse_forward`, `full_experimental`; selectors `legacy`, `branch_fair`; experiments A–H; online JSON plus evaluator-only JSON.

- [ ] Write failing config validation, subset, fixed-budget, GT A/B/absent byte-equality, and Phase 1 compatibility tests.
- [ ] Wire modules in experiment order and freeze online artifacts before importing evaluator inputs.
- [ ] Serialize graph/unit ledgers, formulas-to-variable parameters, timings, RSS, and candidate gain by module.
- [ ] Run all Phase 2 and legacy compatibility tests.

### Task 9: CADETS E3 experiment and report

**Files:** Generate `output/a-rasp-cross-domain-phase2-20260915/`, `candidate-miss-taxonomy.json`, `candidate-miss-taxonomy.md`; create `docs/a-rasp-cross-domain-phase2-results.md`.

**Interfaces:** Frozen 18 ORTHRUS alerts/9 packets, CADETS 06/12/13 only, budgets 5/10/20/30%, A–H ablations and benign-like probes.

- [ ] Reproduce and hash Phase 1 before running Experiment A.
- [ ] Run A–H sequentially, enabling motifs only when taxonomy supports their failure classes.
- [ ] Run budget sweep, per-scenario evaluation, GT mutation/absence replay, determinism, and bounded benign-like probes.
- [ ] Profile any variant several times slower than baseline and record peak RSS.
- [ ] Run the full suite, artifact hash checks, `compileall`, and `git diff --check`.
- [ ] Write the 21-section result report and make a gate recommendation without changing the default.

## Self-review

All requested online modules, the offline-only taxonomy, A–H ablations, four budgets, 18 required test behaviors, required metrics, leakage boundary, performance constraints, and final gate map to explicit tasks. Names and data flow are consistent with the design; optional Steiner and regime modeling are excluded until the core gate is evaluated.
