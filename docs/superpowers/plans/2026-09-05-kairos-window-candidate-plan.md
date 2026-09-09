# KAIROS Window Candidate Construction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace per-alert full traversal with bounded window-context construction and optional shared-state multi-source expansion while preserving independent rarity, diffusion, pruning, and evaluation.

**Architecture:** Parse mapped KAIROS groups into investigation windows, stream time-indexed events into a deduplicated candidate accumulator, and optionally expand from all alerts with shared frontier/state/cache. Persist progress and incomplete diagnostics before scoring. Existing POI bidirectional mode remains available.

**Tech Stack:** Python 3.10, SQLite, pytest, psutil.

**Spec:** User requirements in the 2026-09-05 conversation turn.

## Global Constraints

- Ground truth is evaluation-only and never participates in online candidate construction.
- `window_context` is the default KAIROS mode.
- Resource stops and interrupts must report `incomplete=true`.
- Candidate inputs stay fixed across pruning ablations.

---

### Task 1: Window metadata and streaming store API

**Files:** `tc_pruning/store.py`, `tc_pruning/window_search.py`, `tests/test_window_search.py`

**Interfaces:** Produces `build_window_context(...) -> WindowSearchResult` and paginated timestamp queries.

- [ ] Write tests for time-boundary correctness, overlap deduplication, and input provenance.
- [ ] Run the focused tests and confirm missing APIs fail.
- [ ] Implement page-wise window loading with event-ID deduplication and progress counters.
- [ ] Run focused tests.

### Task 2: Shared-state optional causal completion

**Files:** `tc_pruning/window_search.py`, `tc_pruning/causal.py`, `tests/test_window_search.py`

**Interfaces:** Produces multi-source expansion using `(direction,node,time-state)` dominance and bounded block cache.

- [ ] Write tests for duplicate-alert reuse, different-time states, union equivalence, and resource truncation.
- [ ] Run tests and confirm failures.
- [ ] Implement shared frontier, state dominance, cache capacity, and explicit resource diagnostics.
- [ ] Run focused tests.

### Task 3: Configuration, evaluation integration, and checkpoints

**Files:** `tc_pruning/config.py`, `tc_pruning/evaluation.py`, `tc_pruning/cli.py`, `configs/tc_pruning_kairos_forward.json`, `tests/test_evaluation_cli.py`

**Interfaces:** Supports `window_context` and `window_context_expand`; emits `candidate_construction` diagnostics and partial checkpoint JSON.

- [ ] Write integration tests proving default window mode, no online ground-truth access, and incomplete reporting.
- [ ] Run tests and confirm failures.
- [ ] Wire candidate construction before unchanged scoring/pruning/evaluation.
- [ ] Run integration and full suites.

### Task 4: Controlled validation and documentation

**Files:** `README.md`, independent result JSON files under `output/tc/`.

**Interfaces:** Documents reproducible single-window and five-window commands and measured metrics.

- [ ] Run synthetic verification.
- [ ] Run one-window `window_context` validation.
- [ ] Run five-window only if resource guards permit.
- [ ] Record measured candidate size, recall, relation evidence, time, memory, truncation, and remaining limitations.
