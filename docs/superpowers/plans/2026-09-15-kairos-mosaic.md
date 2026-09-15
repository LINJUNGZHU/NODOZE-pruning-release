# KAIROS-MOSAIC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and evaluate a deterministic, GT-isolated KAIROS-native investigation and minimal-graph compression pipeline on CADETS E3.

**Architecture:** Parse native KAIROS event losses and anomalous queues into an evidence field, map unambiguously to local raw provenance events, construct source/target/long-gap temporal corridors, and select the smallest proof-carrying graph that meets robust multiobjective targets. Keep raw-event and DepImpact-compatible projected-edge costs separate, and join ORTHRUS/PDF labels only in a frozen offline evaluator.

**Tech Stack:** Python 3.12, dataclasses, SQLite, PyTorch/PyG only for frozen KAIROS inference, pytest, JSON/JSONL artifacts.

**Spec:** `docs/kairos-mosaic-design.md`

## Global Constraints

- Dataset is DARPA TC CADETS E3 development only; report scenarios 06/12/13 separately.
- Do not modify A_rasp defaults or delete Phase 2 negative-result modules.
- Online modules must not import KAIROS evaluation/attack lists, ORTHRUS/PDF/DepImpact GT, or offline evaluators.
- Ambiguous native-to-raw mappings are rejected.
- Every path/corridor/demand must retain strictly replayable raw event IDs.
- Raw event count and projected edge count are always reported together.
- Current PDF critical-edge manifest is `PARTIAL_POSITIVE_GT`; unlabeled edges are not FP.
- Parameters are frozen label-free; 20% is legacy-only, not the primary optimization.

---

### Task 1: Native KAIROS evidence and deterministic mapping

**Files:**
- Create: `tc_pruning/detectors/__init__.py`
- Create: `tc_pruning/detectors/kairos_adapter.py`
- Create: `scripts/export_kairos_evidence.py`
- Test: `tests/test_kairos_native_adapter.py`
- Test: `tests/test_kairos_gt_isolation.py`

**Interfaces:**
- Consumes reconstruction window text files, `evaluation.log` queue declarations, and `ProvenanceStore`.
- Produces `KairosEvidence`, `KairosMappingAudit`, `KairosEvidenceField`, and `NativeKairosAdapter.load_and_map()`.

- [ ] Write tests with exact tuple mapping, bounded-tolerance mapping, ambiguous rejection, percentile/queue preservation, deterministic hashes, and an AST forbidden-import scan.
- [ ] Run `PYTHONPATH=. pytest -q tests/test_kairos_native_adapter.py tests/test_kairos_gt_isolation.py` and verify collection or symbol failures.
- [ ] Implement a streaming `ast.literal_eval` parser and mapping tiers. Normalize KAIROS semantic strings to local node labels; issue one indexed time/relation query per timestamp bucket; accept only singleton matches.
- [ ] Add canonical JSON export with SHA-256 over source files, mapping rows, and output evidence.
- [ ] Run the focused tests and verify all pass.
- [ ] Commit adapter, exporter, and tests.

### Task 2: Evaluation projection and Ground Truth contracts

**Files:**
- Create: `tc_pruning/investigation/edge_projection.py`
- Create: `tc_pruning/evaluation_protocol.py`
- Test: `tests/test_evaluation_edge_projection.py`
- Test: `tests/test_edge_groundtruth_protocol.py`

**Interfaces:**
- Consumes raw `StoredEdge` rows and explicit `GroundTruthCompleteness`.
- Produces `ProjectedEdge`, `EvaluationEdgeProjection.project()`, `CompleteEdgeMetrics`, and `PartialPositiveMetrics`.

- [ ] Write failing tests proving RAW one-to-one projection, merge-window boundaries, preservation of raw IDs, complete-GT identities, and partial-GT prohibition of FP/precision.
- [ ] Implement `RAW_EVENT` and `DEPIMPACT_COMPATIBLE` projection keyed by `(src,dst,normalized_relation,floor(timestamp/window))`.
- [ ] Implement complete and partial evaluators. Complete evaluation asserts `TP+FN=|GT|` and `TP+FP=#Edges`; partial evaluation emits `known_tp`, `known_fn`, `unlabeled_output_edges`, `known_recall`, and `projected_edge_count` only.
- [ ] Run focused tests and commit.

### Task 3: Anchor components, target matching, and long-short history

**Files:**
- Create: `tc_pruning/investigation/kairos_components.py`
- Create: `tc_pruning/investigation/target_compatibility.py`
- Create: `tc_pruning/investigation/temporal_memory.py`
- Test: `tests/test_kairos_anchor_components.py`
- Test: `tests/test_target_conditioned_compatibility.py`
- Test: `tests/test_long_short_temporal_memory.py`

**Interfaces:**
- Consumes mapped `KairosEvidence`, node metadata, and pre-cutoff historical edges.
- Produces `KairosAnchorComponent`, `TargetMatchFeatures`, `TargetConditionedCompatibility.score()`, `RarePairHistoryKey`, and `LongShortTemporalMemory.score()`.

- [ ] Write failing tests showing queue members merge, elapsed-time-only evidence does not merge, lineage/resource/endpoint compatibility raises target rank, log-time preserves long-gap signal better than exponential decay, and short/long state remains separate.
- [ ] Implement deterministic union-find components using queue, shared entity plus strict time, summary component, and a configured compatibility threshold.
- [ ] Implement individually auditable target features normalized to `[0,1]`; do not consume labels.
- [ ] Implement exact short cache and logarithmic long-history buckets/reservoir with the six required gap bins and explicit fusion.
- [ ] Run focused tests and commit.

### Task 4: Deterministic inverse coverage and causal corridors

**Files:**
- Create: `tc_pruning/investigation/inverse_coverage.py`
- Create: `tc_pruning/investigation/causal_corridors.py`
- Create: `tc_pruning/investigation/kairos_envelope.py`
- Test: `tests/test_source_aware_inverse_coverage.py`
- Test: `tests/test_causal_corridors.py`

**Interfaces:**
- Consumes `InvestigationGraphs`, anchor components, target scores, and temporal-memory scores.
- Produces `InverseRoot`, `SourceAwareInverseCoverage.explain()`, `CausalCorridor`, `PathBundle`, and `InvestigationEnvelope`.

- [ ] Write failing tests for multi-component root explanation, coverage saturation, unsupported-root forward rejection, strict-time k-shortest corridors, equal-time rejection, high-order proof flags, and raw replay witnesses.
- [ ] Implement deterministic reverse label propagation that ranks roots by explained evidence mass and diversity and stops on marginal explanation gain/resource cap.
- [ ] Implement compatibility-gated temporal path search. Edge cost is used only for proposal and combines bounded normality/hub penalties divided by bounded KAIROS/target/rare-pair/A_rasp support.
- [ ] Build the envelope from native evidence, source explanations, compatible corridors, supported forward bridges, and limited alternative paths; motifs remain proof flags.
- [ ] Run focused tests and commit.

### Task 5: Robust multiobjective trajectory and certified safe deletion

**Files:**
- Create: `tc_pruning/investigation/mosaic_selector.py`
- Create: `tc_pruning/investigation/safe_reducer.py`
- Create: `tc_pruning/investigation/investigation_state.py`
- Test: `tests/test_mosaic_multiobjective_selector.py`
- Test: `tests/test_certified_safe_reducer.py`
- Test: `tests/test_investigation_state.py`

**Interfaces:**
- Consumes envelope evidence units, target vector `ObjectiveTargets`, and path bundles.
- Produces `ObjectiveVector`, `SelectionCheckpoint`, `QualitySizeFrontier`, `RobustMultiobjectiveSelector.select_trajectory()`, `CertifiedProgressiveReducer.reduce()`, and incremental `InvestigationState`.

- [ ] Write failing tests where weighted-sum choice would starve one objective, branch 101 has lower gain than branch 1, path prize protects the unique witness, safe deletion removes redundancy but rejects a bridge deletion, and repeated queue updates produce deterministic churn accounting.
- [ ] Implement structural representative prefiltering with top-K lists per branch/component/relation/corridor and a mandatory-bridge lane; never allocate a heap entry per raw event.
- [ ] Implement sparse objective counters, max-min normalized gain, monotone incremental checkpoints, and minimum-target prefix search.
- [ ] Implement removal-risk ordering plus full objective and strict witness checks after each tentative deletion.
- [ ] Run focused tests and commit.

### Task 6: Progressive propagation view

**Files:**
- Create: `tc_pruning/investigation/progressive_purification.py`
- Test: `tests/test_progressive_propagation_purification.py`

**Interfaces:**
- Consumes immutable `InvestigationGraphs`, KAIROS/target support, and root/candidate ranking callback.
- Produces `PurificationResult` with per-round weights, stability, downweighted count, and stop reason.

- [ ] Write failing tests that G_full never changes, interference weights decrease, unique evidence is protected, and oscillating top sets stop purification.
- [ ] Implement two-to-four rounds of derived-weight updates and Jaccard stability monitoring without deleting raw edges.
- [ ] Run focused tests and commit.

### Task 7: Online runner, frozen evaluator, and CADETS E3 ablations

**Files:**
- Create: `configs/kairos_mosaic.json`
- Create: `scripts/run_kairos_mosaic.py`
- Create: `scripts/evaluate_kairos_mosaic.py`
- Create: `scripts/reconstruct_kairos_frozen_days.py`
- Test: `tests/test_kairos_mosaic_runner.py`
- Test: `tests/test_kairos_mosaic_evaluator.py`
- Test: `tests/test_kairos_mosaic_performance.py`

**Interfaces:**
- Online runner consumes only DB, native KAIROS artifact, frozen config, and Track A incident inputs where applicable.
- Offline evaluator consumes frozen online artifacts and explicit ORTHRUS/PDF truth.
- Produces K0–K6, R0–R4, S0–S5 results, candidate ceiling decomposition, FN/known-FN versus projected-edge frontier, timings, RSS, and hashes.

- [ ] Write failing tests for no-GT CLI/imports, canonical determinism, ablation schema, candidate/selection FN decomposition, frontier target points, legacy metric compatibility, and a synthetic large-query selector under five seconds.
- [ ] Implement a frozen-model reconstruction helper for missing CADETS days that imports only KAIROS model/inference code, records model hash/seed/environment, and writes native loss windows without invoking official evaluation.
- [ ] Implement online runner using one incremental trajectory per input configuration and serialize mapping/component/root/corridor/objective/reducer audits separately from performance telemetry.
- [ ] Implement offline evaluator with explicit partial-positive semantics and Track A/B separation.
- [ ] Run focused tests, then execute KAIROS day 12/13 reconstruction if absent, native mapping, all ablations, and offline evaluation.
- [ ] Profile any query over ten seconds and apply only architecture-preserving optimizations.
- [ ] Commit runner/evaluator/config/tests; keep generated outputs outside Git.

### Task 8: Dense results report and final verification

**Files:**
- Create: `docs/kairos-mosaic-results.md`
- Modify: `README.md`

**Interfaces:**
- Consumes frozen experiment JSON, mapping audit, performance telemetry, and Phase 2 hashes.
- Produces the requested report and an opt-in README pointer without changing defaults.

- [ ] Generate the report sections: baseline, KAIROS reproduction/mapping, metric alignment/GT completeness, candidate ceiling, K/R/S ablations, long-gap/target/corridor studies, safe deletion, frontier, costs, scenarios, performance, isolation, negative results, SOTA validity, and the smallest supported method.
- [ ] Explicitly answer every question in specification section 48 and distinguish candidate FN from selection FN.
- [ ] Run `PYTHONPATH=. pytest -q`, artifact hash validation, AST isolation checks, JSON schema assertions, and `git diff --check`.
- [ ] Commit documentation and report the branch/worktree without merging or changing defaults.
