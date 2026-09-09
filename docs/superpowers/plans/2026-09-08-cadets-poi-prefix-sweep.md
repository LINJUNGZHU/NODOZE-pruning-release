# CADETS POI Prefix Sweep Implementation Plan

> **Execution note:** This workspace is not a Git repository, so worktree and commit steps are unavailable. The user approved direct uninterrupted execution in the current workspace.

**Goal:** Implement and run a three-day CADETS experiment that incrementally adds report-derived POIs and identifies the smallest prefix attaining each day's maximum complete attack-path restoration at a fixed 20% raw-event budget.

**Architecture:** Add a focused orchestration module above the existing experiment API. It validates deterministic POI timelines, creates fixed report-aligned evaluation manifests, runs RDP-Guard once for every prefix without redundant method ablations, computes seeded versus unseeded terminal-path metrics, and writes auditable timestamped summaries. Keep Ground Truth strictly on the post-pruning evaluation side.

**Tech Stack:** Python 3, dataclasses, JSON/CSV, pytest, the existing SQLite provenance store, RDP-Guard experiment runner, and CLI.

---

## Task 1: Specify prefix and summary behavior with failing tests

**Files:**
- Create: `tests/test_poi_prefix.py`
- Create: `tc_pruning/poi_prefix.py`

1. Write a test that a POI pool is resolved from the real store in timestamp order and rejects missing, duplicate, or out-of-order events.
2. Write a test that every generated prefix manifest has exactly the prefix seeds and the same declared fixed window.
3. Write literal path fixtures proving selected-terminal and unselected-terminal path retention are counted separately and an empty unselected denominator returns `None`.
4. Write a curve fixture proving the minimum sufficient prefix is the earliest certificate-valid, budget-feasible row attaining the maximum restored-path count.
5. Run `python -m pytest tests/test_poi_prefix.py -q` and confirm RED because the orchestration module does not exist.

## Task 2: Implement validated POI/reference preparation

**Files:**
- Create: `tc_pruning/poi_prefix.py`
- Modify: `tests/test_poi_prefix.py`

1. Add strict dataclasses and JSON loader for the sweep specification.
2. Resolve all POIs from SQLite, validate deterministic chronology, and construct prefix annotations with one shared fixed window.
3. Load the existing UBC base manifest and build one fixed time-respecting, report-POI-anchored reference path per full-pool POI.
4. Persist both the prefix manifests and fixed reference manifest with explicit source/quality/window-extension metadata.
5. Run the focused tests until GREEN.

## Task 3: Add lightweight experiment mode and sweep orchestration

**Files:**
- Modify: `tc_pruning/evaluation.py`
- Modify: `tests/test_evaluation_cli.py`
- Modify: `tc_pruning/poi_prefix.py`
- Modify: `tests/test_poi_prefix.py`

1. Add a failing experiment test showing `include_method_comparison=False` emits no ablation rows while retaining the primary RDP-Guard result.
2. Add the optional parameter with a default of `True` so existing CLI and tests retain current behavior.
3. Implement sequential prefix execution, namespaced progress writes, per-prefix JSON persistence, metric extraction, marginal gains, and minimum-sufficient selection.
4. Write JSON, CSV, and Markdown aggregate summaries.
5. Run focused tests until GREEN.

## Task 4: Wire the CLI and real CADETS specification

**Files:**
- Modify: `tc_pruning/cli.py`
- Create: `configs/cadets_e3_poi_prefix_sweep.json`
- Modify: `README.md`
- Modify: `tests/test_poi_prefix.py`

1. Add `poi-prefix-experiment --db --spec --config --output-dir`.
2. Add a CLI integration test using a small real SQLite fixture and assert the emitted summary artifact, not parser internals.
3. Create the three-day spec for UBC-06, UBC-12, and extended UBC-13 using the report-derived POI pools and existing base manifests.
4. Document the foreground command, detached timestamped command, progress inspection, and result interpretation.
5. Check `python -m tc_pruning.cli poi-prefix-experiment --help` and rerun focused tests.

## Task 5: Verify and run all 14 prefixes

**Files:**
- Runtime results under: `output/tc/poi-prefix-sweep/`
- Runtime logs under: `logs/`

1. Run `python -m pytest tests -q` and confirm all tests pass.
2. Launch the three-day sweep detached with a single `YYYY-MM-DD_HH-MM-SS` identifier shared by log and output directory.
3. Monitor the process, progress file, and log through all 14 prefix runs.
4. Validate that summary rows cover `3 + 8 + 3 = 14` unique prefixes and that every reported output file parses.
5. Report the exact command, final log/result paths, per-day curves, minimum sufficient POI counts, budget fidelity, complete-path retention, and unseeded-path restoration.
