# Reference Subgraph Completeness Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans to implement these independent tasks.

**Goal:** Evaluate and display retained reference subgraphs, including branching dependencies that a single surviving path can conceal.

**Architecture:** Add an offline sidecar evaluator over immutable v2 selections. Separate the small graph metric core, frozen-run adapter, and HTML integration; retain all old reports and source hashes.

**Tech Stack:** Python, NumPy, Matplotlib, existing Flask static routes, native JavaScript/SVG, pytest and Playwright.

**Spec:** `docs/superpowers/specs/2026-09-30-reference-subgraphs-design.md`

## Global constraints

- Do not modify frozen scoring implementations, v2 evaluator, reference derivation, or previous experiment artifacts.
- Validate the whole registered matrix before reading references; no labels influence the saved selections.
- No independent complete-attack claim, missing E5 results, or private event details in public artifacts.
- Keep native and augmented denominators separate and keep singletons and unresolved source events visible.

## Review focus

- Missing parallel branch with surviving alternative: reachability can remain perfect while exact completeness fails.
- Reverse/equal/unknown timestamps and explicit host conflicts: no invented temporal route.
- Removing a transitive-reduction intermediate: evaluate the full feasible-transition graph.
- Changed frozen files/report/reference after validation: fail before publishing mismatched results.
- Wrong-case or stale asynchronous HTML sidecar: reject it without hiding the existing retained graph.

## Tasks

- [x] Core: write failing tests in `tests/test_subgraph_evaluation.py`; implement `tc_pruning/subgraph_evaluation.py`; cover branch/merge, singletons, LINEAGE, temporal order, host identity, exact completion and reachability.
- [x] Adapter: write failing frozen-fixture tests in `tests/test_evaluate_reference_subgraphs.py`; add `scripts/evaluate_reference_subgraphs.py` with aggregate and optional local sidecar output. Match existing reference/source/decision provenance and retain stage-loss counts.
- [x] Presentation: extend the existing workbench and retained-chain pages through additive sidecar loading; add browser tests for metrics, missing branches, source mismatch, N/A, mobile layout and exact decision linkage.
- [x] Research artifacts: add `scripts/plot_reference_subgraphs.py`; evaluate all 9 cases and 2520 frozen decisions, generate native/augmented curves, and document actual path-versus-subgraph differences without retuning.
- [x] Verification: run the full Python suite, actual-service browser checks, aggregate consistency/privacy checks and independent review. Sync owned files to the original workspace, then publish code and aggregate artifacts to the authorized existing GitHub branch.
