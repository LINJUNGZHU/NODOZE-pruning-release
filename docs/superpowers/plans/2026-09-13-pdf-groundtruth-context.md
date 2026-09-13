# PDF Ground Truth and Context Investigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement task-by-task.

**Goal:** Assess real attack recovery using uploaded reference sources and add a measured context graph.
**Architecture:** A PDF-bound reference resolver feeds evaluation only. A label-independent context selector consumes existing detector witnesses. Uploaded DARPA labels are evaluated in a separate reproducible tool.
**Tech Stack:** Python, SQLite, pypdf, existing Flask/JavaScript frontend.
**Spec:** `docs/superpowers/specs/2026-09-13-pdf-groundtruth-context-design.md`.

## Global Constraints

Unknown labels stay unknown; preserve failed versus successful actions; PDF/ZIP never enter inference. Preserve raw event IDs and strict temporal evidence. Do not merge UUIDs by PID. Keep unrelated edits.

## Task 1: PDF reference and evaluation

Files: `poi/optc-pdf-reference.json`, `tc_pruning/pdf_groundtruth.py`, `tests/test_pdf_groundtruth.py`, `webapp/scripts/evaluate_pdf_groundtruth.py`, `tc_pruning/attack_evaluation.py`.

- [x] Test `resolve_pdf_reference(edges, reference)` on host/PID collisions, multiple matching C2 actors, out-of-window agents, resource roles and unknown labels. `assert result['labels'].get(unrelated) is None`; `assert len(ambiguous['node_ids']) == 2` and no forced positive.
- [x] Transcribe page-cited agents/activities from the four-page PDF; validate every source excerpt and SHA256 with `validate_reference(pdf_path, reference)`.
- [x] Implement resolver with explicit observed status and evidence IDs; evaluate predictions only afterward via `node_metrics`.
- [x] Evaluate rules/neural/multiview across four windows, write JSON and CSV; integrate PDF benchmark as primary UI source.

## Task 2: Evidence-preserving context subgraph

Files: `tc_pruning/context_graph.py`, `tests/test_context_graph.py`, `webapp/scripts/evaluate_pdf_groundtruth.py`（共用对照入口）, backend/frontend integration.

- [x] Test `build_context(report, edges, config=None)` preserves every prediction witness and blocks shared-resource fanout, and `verify_context(context, report, edges)` rejects missing/foreign event IDs.
- [x] Implement process-waypoint graph, exact event membership and typed interaction bundles; every bundle stores its full ID list, count and time range. Include context-only process roles separately.
- [x] Measure default and parameter ablations against PDF reference events and existing retained edges; include resource/edge denominators, time and compression.
- [x] Add context graph selection to existing graph pane and compact endpoint/export; raw event retrieval remains available.

## Task 3: Uploaded archive, research and integration

Files: `webapp/scripts/evaluate_uploaded_groundtruth.py`, its tests, `docs/pdf-groundtruth-study.md`, machine-readable experiment outputs.

- [x] Audit all 12 archive CSVs and evaluate matching local outputs. Distinguish missing data, candidate coverage and retained labeled nodes.
- [x] Consolidate 15-paper primary-source reading inventory and actionable method comparisons, including inaccessible full texts.
- [x] Run focused/full tests and desktop/mobile browser workflow; check exported references.
- Final integration after verification: commit, fast-forward main, push GitHub, refresh live caches and verify service.
