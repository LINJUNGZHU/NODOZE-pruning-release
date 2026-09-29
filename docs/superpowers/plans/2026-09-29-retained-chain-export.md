# Retained Chain Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans task-by-task. User authorized autonomous implementation.

**Goal:** Export and display the exact retained event graph and its temporal paths independently of reference labels.

**Architecture:** A pure builder validates candidate rows and a frozen selection, forms a deterministic path cover, then a writer emits local JSON/CSV/GraphML with hashes. A CLI reuses frozen-run validation. The browser consumes a local catalog and the same JSON artifact.

**Tech Stack:** Python, numpy, stdlib XML/CSV, existing Flask static routes, vanilla JavaScript.

**Spec:** docs/superpowers/specs/2026-09-29-chain-workbench-v2-design.md

## Global Constraints

- Labels are never inputs to retained-chain reconstruction.
- Export every selected event, including singleton paths; no deleted event may reappear.
- Exact integer timestamps, strict directed time continuity, reverse EXECUTE only for causal direction.
- Raw event exports stay local and ignored; no original user data is deleted.

## Review Focus

- Equal timestamps must not create false causal steps.
- A branching graph must not be serialized as a false single path.
- Selected isolated events must remain visible and counted.
- Malformed masks, duplicate IDs, infeasible budgets and noninteger timestamps must fail.
- Existing export directories must remain unchanged on attempted overwrite.

### Task 1: Exact event and path exports

**Files:** tc_pruning/retained_chains.py; tests/test_retained_chains.py.
**Interfaces:** build_retained_artifact(rows, selected, scores=None, *, case_id, method, budget_edges, bundles=()) -> dict; write_retained_export(directory, artifact) -> manifest dict.

- [ ] Write tests for exact event union, branches/equal time, EXECUTE, singleton, input validation and deterministic reordering; run to confirm missing module failure.
- [ ] Implement a greedy temporal path cover over selected events, publish endpoint availability only after an equal-time batch; sort deterministic ties by event ID. Preserve optional fully retained observed bundles separately.
- [ ] Write JSON/CSV/GraphML and manifest hashes with refusal to overwrite; test round-trip identities and XML escaping.
- [ ] Run focused tests and review union/path invariants.

### Task 2: Frozen decisions CLI and local viewer

**Files:** scripts/export_retained_chains.py; webapp/frontend/retained-chains.html/.css/.js; browser regression.
**Interfaces:** CLI --frozen DIR --method NAME --budget RATIO --output NEWDIR; viewer catalog includes artifact URL and JSON/CSV/GraphML download URLs.

- [ ] Test export from a small existing frozen synthetic run and rejection of a tampered source.
- [ ] Validate source, load exact arrays, invoke Task 1 without annotations; no recomputation of selection.
- [ ] Build accessible case selector, path list, precise event table, semantic labels, POI markers and downloads; distinguish observed paths from complete attack truth.
- [ ] Check browser against actual exports, branches, missing catalog and mobile layout.

### Task 3: Integration and publication

- [ ] Export representative existing real and synthetic decisions locally; verify event counts against frozen masks.
- [ ] Add clear links from the experiment page and workspace index.
- [ ] Run full tests and independent review; publish code plus aggregate manifests only, retain raw exports locally.
