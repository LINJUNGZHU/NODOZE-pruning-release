# RDP-Guard Research Evidence and Prefix Stability Implementation Plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist every edge score with verifiable provenance and replace unstable joint POI scoring with a monotone, bounded-churn prefix workflow.

**Architecture:** Keep the existing graph builder and signal implementations, add a deterministic evidence-writer boundary, extend pruning results with explanations/certificate states/stability diagnostics, and make the prefix runner pass only online state between prefixes. Ground truth remains downstream of pruning.

**Tech Stack:** Python 3, dataclasses, JSON/JSONL, gzip, hashlib, pytest, SQLite-backed provenance store.

**Spec:** `docs/superpowers/specs/2026-09-08-edge-ledger-prefix-stability-design.md`

## Global Constraints

- [x] Do not read ground truth in scoring, aggregation, selection, or ledger classification.
- [x] Charge every raw event, including atomic-group expansion and certificate bridges, to the same budget.
- [x] Use deterministic ordering and atomic writes for all evidence artifacts.
- [x] Preserve existing user files and do not require a Git worktree; this checkout is not a Git repository.
- [x] Mark CCF-A readiness as an evaluation target, not an acceptance or publication claim.

## Task 1: Specify and test the complete score ledger

**Files:** `tests/test_score_ledger.py`, `tc_pruning/score_ledger.py`

- [x] Add failing tests for complete unique rows, deterministic rank/ties, threshold-plus-quantile high-index equality, decision joins, atomic gzip output, and SHA-256 manifest verification.
- [x] Implement rarity evidence records and a deterministic gzip JSONL writer.
- [x] Write the high-anomaly index and manifest last using atomic replacement.
- [x] Run `python -m pytest tests/test_score_ledger.py -q` and make it pass.

## Task 2: Add score provenance and selection explanations

**Files:** `tests/test_diffusion_pruning.py`, `tests/test_rdp_guard.py`, `tc_pruning/rdp_guard.py`, `tc_pruning/pruning.py`

- [x] Add failing tests for noisy-OR monotonicity and deterministic local-winner provenance.
- [x] Add failing tests that every retained edge has a reason and zero-score groups are not used in prefix-stable mode.
- [x] Implement local score aggregation and selection-reason capture.
- [x] Fix per-alert component/provenance mismatch.
- [x] Run the focused pruning and RDP-Guard tests.

## Task 3: Implement bounded-churn prefix selection

**Files:** `tests/test_diffusion_pruning.py`, `tc_pruning/pruning.py`

- [x] Add failing tests for prior-set preference, raw budget, atomic groups, deterministic ties, and reported churn-bound compliance.
- [x] Add prior kept IDs, churn slack, and positive-score-only inputs to `adaptive_prune`.
- [x] Record added, removed, Jaccard, allowed removal, unused budget, and bound status.
- [x] Run focused tests and small brute-force invariants.

## Task 4: Make certificate semantics strict

**Files:** `tests/test_diffusion_pruning.py`, `tc_pruning/pruning.py`, `docs/EVALUATION_PROTOCOL_V2.md`

- [x] Change the disconnected-candidate regression to expect `candidate_disconnected` and an invalid certificate.
- [x] Test `valid`, `poi_only`, `budget_infeasible`, `missing_poi`, and `unordered_multi_poi` states.
- [x] Implement the state machine, persist witnesses, and expose strict multi-stage validity.
- [x] Align the protocol text with the implementation.

## Task 5: Integrate evidence and prefix-stable scoring

**Files:** `tests/test_config.py`, `tests/test_evaluation_cli.py`, `tests/test_poi_prefix.py`, `tc_pruning/config.py`, `tc_pruning/evaluation.py`, `tc_pruning/poi_prefix.py`, `tc_pruning/cli.py`, `configs/tc_pruning_poi_alert.json`

- [x] Add failing config tests for ledger thresholds, prefix stability, churn slack, and strict booleans.
- [x] Make the POI prefix manifest create chronological singleton scoring groups over one fixed window.
- [x] Aggregate local edge scores with noisy-OR and retain immutable local-score digests.
- [x] Pass prior retained IDs only between consecutive prefixes of the same scenario.
- [x] Write and deep-verify a ledger directory for every prefix and include its manifest in the JSON report.
- [x] Add prefix monotonicity and churn columns to JSON/CSV/Markdown summaries.
- [x] Ensure the regular `experiment` CLI writes a sibling ledger directory.
- [x] Run all focused integration tests.

## Task 6: Document the submission-grade evaluation boundary

**Files:** `README.md`, `docs/PUBLICATION_EVALUATION.md`

- [x] Document score-ledger layout and verification commands.
- [x] Document baselines, factorial ablations, datasets, statistical tests, runtime/memory reporting, and label limitations.
- [x] Explicitly distinguish heuristic importance from calibrated attack probability.

## Task 7: Verify and execute CADETS E3

**Files:** `scripts/run_cadets_poi_prefix_sweep.sh`, generated `logs/` and `output/tc/poi-prefix-sweep/`

- [x] Run `python -m pytest tests -q` from the project root (241 passed before launch).
- [ ] Launch the 14-prefix experiment detached with `setsid`, a `YYYY-MM-DD_HH-MM-SS` run ID, and stdout/stderr redirected to the matching log.
- [ ] Validate process status, all 14 reports, ledger row counts/hashes, budgets, certificate states, score monotonicity, and churn bounds.
- [ ] Compare path retention and churn against the 2026-09-08 11:29:29 baseline without using those offline labels to alter selection.
- [ ] Record the exact launch, status, and inspection commands in the final handoff.

Execution note: the user explicitly requested direct implementation and execution without a design discussion, so this approved plan is executed inline with test-first checkpoints.

## Task 8: Correct branch-aware certificate semantics

- [x] Diagnose the UBC-13 linear-sequence failure against the DARPA report and candidate graph.
- [x] Replace late nginx/pEja endpoints with the first report-aligned C2 events before the payload write/execute bridge.
- [x] Add a predeclared, disjoint causal path cover and retain strict within-path temporal witnesses.
- [x] Add chain/forest/singleton topology fields and fail closed on any disconnected declared path.
- [x] Upgrade the independent sweep validator and summary schema to v3.
- [x] Make the detached launcher gate success on independent validation.
- [x] Pass the UBC-13 three-prefix smoke run and all repository tests.
