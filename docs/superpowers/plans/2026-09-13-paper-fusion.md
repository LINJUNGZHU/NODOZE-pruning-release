# Paper-inspired Multi-view Implementation Plan

> Execute inline with executing-plans; standing user authorization replaces approval checkpoints.

**Goal:** Add independently calibrated learned views and verifiable stage summaries to the existing investigation workflow.

**Architecture:** Separate feature extraction/model fitting, frozen inference, and evidence narrative. Existing inference owns process predictions, paths and evaluation; the UI exposes the new evidence without hiding baseline results.

**Tech Stack:** Python, NumPy, PyTorch, Flask, existing JavaScript frontend.

**Spec:** `docs/superpowers/specs/2026-09-13-paper-fusion-design.md`.

## Global constraints

No attack labels in fitting/calibration. Use strict chronological training/validation/calibration. Preserve both label denominators, existing rules and unrelated user changes. State all departures from the papers.

## Task 1: Learned views and fusion

Create `tc_pruning/multiview.py`, `webapp/scripts/train_multiview.py`, `tests/test_multiview.py`.

- [x] Write failing tests for `causal_samples(edges)` (same-time events cannot see each other; changed current action leaves input unchanged), `structural_graphs(edges)` (renaming metadata leaves vectors unchanged), and `fusion_decision(scores, calibration)` (constant dimensions do not vote).
- [x] Run `python -m pytest -q tests/test_multiview.py` and confirm missing-feature failures.
- [x] Implement normalized relational snapshots, masked reconstruction model, causal relation MLP, attribute KNN, and seven-dimension frozen calibration. `score_nodes(edges, directory=None)` returns per-node scores, votes and evidence IDs plus model provenance.
- [x] Test fit/load round trip and reject corrupt weights or windows overlapping calibration.
- [x] Train using the existing SQLite temporal partitions and save manifest, weights and training diagnostics.

## Task 2: Integration and evidence stages

Modify `tc_pruning/attack_inference.py`; create `tc_pruning/attack_story.py` and `tests/test_attack_story.py`.

- [x] Test a `multiview` report using supplied scores and verify that rules/POI do not override its predictions.
- [x] Test stage construction with genuine creation/file/flow events and reject fabricated IDs, stages or timestamps.
- [x] Add detector integration and `build_story(report, edges)`; each stage includes observed action, exact references and validation status.
- [x] Extend report verification to recompute story facts from raw events.

## Task 3: Evaluation and presentation

Create `webapp/scripts/evaluate_multiview.py`, `docs/paper-fusion-study.md`, and machine-readable results. Modify backend availability and frontend detector/view/stage displays.

- [x] Evaluate frozen new model, individual views, rules and prior neural baseline across four windows, reporting both GT projections, event coverage and runtime.
- [x] Finish browser assertions for detector switching, view scores, stage links and export; check desktop/mobile overflow.
- Final integration: fast-forward main and push after checks; full Python suite is 420/420 and independent review is clear.
