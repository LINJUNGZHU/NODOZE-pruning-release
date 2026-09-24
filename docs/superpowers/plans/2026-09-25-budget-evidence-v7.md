# Budget Evidence v7 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute first-stage P0/P1/P2 controlled experiments with raw-event temporal certificates and separate candidate/score/path/objective attribution.

**Architecture:** Reuse frozen ledger, score and route modules. New small modules create deterministic views, group references, legal alternative witnesses and fixed snapshots; a label-free runner publishes decisions, then separate evaluator and diagnosis read the local reference.

**Tech Stack:** Python 3.12, NumPy 1.26.4, SciPy 1.14.1, pytest; existing pcst_fast/NetworKit retained.

**Spec:** `docs/superpowers/specs/2026-09-25-budget-evidence-v7-design.md`.

## Global Constraints

- Preserve all v4-v6 code and artifacts; no default web/CLI changes.
- Same oracle POI, ledger and raw ID cap; `LINEAGE:` counts in ledger budget and reports separately.
- Selection code cannot read local reference; manifests/decisions published atomically.
- Five cases are development data; missing truth makes official SPARSE-equivalent metrics null.
- Fixed E0=20, E2=40, E3=60 core configurations; sensitivities are separate.

## Review Focus

- Equal timestamps cannot form a strict route: path validator test in Task 2.
- Host-qualified nodes cannot silently merge: group and witness tests in Tasks 1–2.
- Positive zero-cost action must be applied once: objective test in Task 3.
- Labels must not affect selected IDs: process separation and regression tests in Tasks 4–5.
- Reused cache with changed source/config must fail: audit/runner test in Task 4.

---

### Task 1: Input audit and candidate views/groups

**Files:** `docs/budget-evidence-v7/input_audit.json`, `tc_pruning/candidate_views.py`, `tc_pruning/deferred_event_groups.py`, `tests/test_candidate_views.py`, `tests/test_deferred_event_groups.py`.

**Interfaces:** `rank_views(primary,rarity,temporal,ties,policy='primary',rrf_c=60)->np.ndarray`; `GroupIndex.from_events(src,dst,relation,timestamp,ties,window_ns,relation_policy)->GroupIndex`, `ranked_descriptors(view_scores)->group IDs`, `members(group)->event indices`.

- [ ] Write failing tests for deterministic RRF/round-robin, bounded 10s total span, relation policy, host-isolated endpoint indices, duplicate ID rejection in loader.
- [ ] Run focused tests and confirm expected missing module/API failure.
- [ ] Implement rank fusion and compact group slices without labels; verify focused tests and full suite.
- [ ] Commit tested modules and frozen design/audit artifacts.

### Task 2: Alternative temporal witnesses

**Files:** `tc_pruning/alternative_witnesses.py`, `tests/test_alternative_witnesses.py`.

**Interfaces:** `build_witnesses(anchor,src,dst,timestamp,poi,back,parent,pivot,links,k)->tuple[Witness,...]`; `validate_witness(witness,...)->bool`. First certificate equals legacy fork union. Upstream/downstream route parents provide later distinct legal alternatives.

- [ ] Write failing tests for k1 exact legacy set, k3 dedup/fallback, strict timestamp, equal-time rejection, host isolation, 223 members individually certified.
- [ ] Run focused RED, implement route tracing and certificate digest, run focused GREEN and full suite.
- [ ] Commit.

### Task 3: Fixed snapshot and objectives

**Files:** `tc_pruning/evidence_objective.py`, `tests/test_evidence_objective.py`.

**Interfaces:** `CandidateSnapshot` stores immutable anchors/groups/certificates/union/hash; `select(snapshot,mandatory,budget,objective,eta)->Selection`; `complete_group` applies OR-of-AND to accepted certificates.

- [ ] Write failing tests for union billing, AND/OR, anchor-only credit, zero-cost action, infeasible/null and small brute-force objective checks.
- [ ] Run RED, implement exact cost and three objectives, run GREEN and full suite.
- [ ] Commit.

### Task 4: Label-free case runner and P0/E2/E3

**Files:** `configs/budget_evidence_v7.json`, `scripts/audit_budget_evidence_inputs.py`, `scripts/run_budget_evidence_v7.py`, `tests/test_budget_evidence_contracts.py`, `docs/budget-evidence-v7/experiment_registry.json`.

**Interfaces:** `--case 0..4 --output-dir PATH [--dry-run]`; immutable manifest, per-selection and witness JSON.gz, source/config/pool hash. Runner compares E0 selected IDs to frozen v6 decisions and fails on mismatch.

- [ ] Write failing tests for config/input hash invalidation, row permutation, unique ID, mandatory overflow, label path prohibition and atomic publication.
- [ ] Run RED; implement CLI and case-wise score/route reuse; run GREEN/full suite.
- [ ] Pilot FD1 and THEIA1 to record actual time/RSS and adjust execution scheduling only; never tune algorithm by labels.
- [ ] Execute E0 20, E2 40, E3 60; archive commands, statuses and errors; commit code/config.

### Task 5: Independent evaluator and stage/oracle diagnosis

**Files:** `scripts/evaluate_budget_evidence_v7.py`, `scripts/diagnose_budget_evidence_v7.py`, `tests/test_budget_evidence_evaluation.py`, `docs/budget-evidence-v7/{results.csv,results.json,candidate_stage_audit.csv,oracle_bounds.csv}`.

**Interfaces:** evaluator consumes frozen selections and reference; diagnosis consumes frozen snapshots and labels only after persistence. All statuses retain null metrics if no selection.

- [ ] Write failing tests for partial-positive precision naming, group any/full, incremental null denominator, synthetic counts, path closure and budget; small label oracle with exact solution and valid bounds.
- [ ] Run RED; implement evaluators, run GREEN/full suite.
- [ ] Evaluate all completed core decisions; export mutually exclusive loss-stage diagnosis and finite-pool oracle on tractable subsets.
- [ ] Commit.

### Task 6: Reporting, profiling and final verification

**Files:** `scripts/profile_budget_evidence_v7.py`, `scripts/report_budget_evidence_v7.py`, `docs/budget-evidence-v7/{baseline_manifest.json,source_manifest.json,profiles.csv,robustness.csv,report.md,reproduce.sh,missing_artifacts.md}`.

- [ ] Build baseline/source manifests with paper versions and adaptation status; verify every result row has matching input/source/config hashes.
- [ ] Profile selected methods with independent processes, record cold/warm scope and peak RSS; graph curves only for experiments actually run.
- [ ] Explain H1-H4, all regressions and remaining blocked work; include paper links and exact CLI.
- [ ] Run full suite, report-row integrity and `git diff --check`; get one independent review if available; commit and keep branch isolated.
