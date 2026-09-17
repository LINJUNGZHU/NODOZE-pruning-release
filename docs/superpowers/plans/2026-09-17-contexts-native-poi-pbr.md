# CONTEXTS Native-POI A_rasp-PBR Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adapt the retained three pruning methods to all official CONTEXTS scenarios using native POI/waypoint labels and offline GT evaluation.

**Architecture:** A pure adapter converts exported Neo4j records into `StoredEdge` and native-label manifests. A runner restores each dump, exports it, seals label-free selector decisions, and only then evaluates the GT subgraph. Existing A_rasp, PBR, branch-fair, projection, and strict-temporal helpers remain the algorithmic core.

**Tech Stack:** Python 3.12, Neo4j Community 5.26.4, Java 17, Cypher HTTP API, pytest.

**Spec:** `docs/superpowers/specs/2026-09-17-contexts-native-poi-pbr-design.md`

## Global Constraints

- Native `POI/WP1/WP2` anchors take priority; KAIROS is legal only when all are absent.
- Online selectors must not receive `GT` labels or offline reference edges.
- Preserve existing CADETS E3 results and selector semantics.
- Use all 20 archive scenarios and one common candidate per scenario.
- Do not report precision, FPR, or F1 from partial-positive GT annotations.

---

### Task 1: Pure CONTEXTS schema adapter

**Files:**
- Create: `tc_pruning/contexts_dataset.py`
- Test: `tests/test_contexts_dataset.py`

**Interfaces:**
- Consumes: Neo4j node/relationship dictionaries.
- Produces: `adapt_contexts_graph(scenario, nodes, relationships) -> ContextsGraph`, `choose_poi_source(...)`, and deterministic native proxies.

- [ ] Write failing tests for exact decimal timestamps, all four causal relation mappings, stable IDs, label separation, native-anchor precedence, and KAIROS fallback rejection when native anchors exist.
- [ ] Run `PYTHONPATH=. pytest tests/test_contexts_dataset.py -q` and confirm missing-module failures.
- [ ] Implement the minimal frozen dataclasses and mappings.
- [ ] Run the focused tests and adjacent PBR tests.

### Task 2: Label-free three-method online comparison

**Files:**
- Create: `tc_pruning/contexts_experiment.py`
- Test: `tests/test_contexts_experiment.py`

**Interfaces:**
- Consumes: `ContextsGraph`, common projection, budgets, native proxies.
- Produces: `run_online_scenario(...)`, branch provenance, A/PBR/C decisions, hashes, time, and RSS.

- [ ] Write failing tests proving GT mutation does not change any online decision hash and that only the three retained methods are emitted.
- [ ] Reuse `_a_rasp`, `a_rasp_evidence`, `pbr_sweep`, and `branch_fair_checkpoints`; add `EVENT_DERIVE` causal support with its own regression test.
- [ ] Use scenario-local frequency counts and mark their provenance explicitly.
- [ ] Run focused and adjacent selector tests.

### Task 3: Offline CONTEXTS GT evaluator

**Files:**
- Modify: `tc_pruning/contexts_experiment.py`
- Test: `tests/test_contexts_experiment.py`

**Interfaces:**
- Consumes: a sealed online record plus offline GT node IDs.
- Produces: GT node/edge recall, strict path families, CONTEXTS time/path buckets, graph size, runtime, and limitations.

- [ ] Write failing tests for GT-edge TP/FN, POI-local forward/backward/anchor paths, and absence of unsupported precision/FPR/F1.
- [ ] Implement strict-time evaluation using the canonical causal direction.
- [ ] Add aggregate calculations that sum counts before deriving recall.
- [ ] Run focused tests.

### Task 4: Neo4j restore/export and formal runner

**Files:**
- Create: `scripts/run_contexts_native_poi_experiment.py`
- Create: `configs/contexts_native_poi_pbr.json`
- Test: `tests/test_contexts_runner.py`

**Interfaces:**
- Consumes: the pinned ZIP/extracted dumps, Neo4j home, and experiment config.
- Produces: resumable per-scenario artifacts, online seal, `evaluation.json`, `summary.md`, status, progress, PID, and log.

- [ ] Write failing fixture-run tests for restore command construction, online-before-offline ordering, resume behavior, and all-scenario completion checks.
- [ ] Implement restore/migrate/start/export/stop orchestration with condition-based readiness checks.
- [ ] Pin archive/config/code hashes in the input manifest.
- [ ] Run fixture tests, then execute the formal 20-scenario run.
- [ ] Verify artifact hashes, all 20 statuses, algorithm set, POI-source audit, and aggregate arithmetic.

