# POI Alert-Context Pruning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a KAIROS-style alert-window pipeline for ordered POI stages, rank it with time-respecting edge diffusion plus rarity, and preserve the ordered stage backbone during pruning.

**Architecture:** Extend POI manifests with incident groups and explicit windows, carry that structure through `AttackAnnotations`, and reuse `window_context` for raw candidate construction. Add an opt-in temporal bidirectional diffusion mode with edge scores, then make pruning reserve consecutive POI-stage paths before score-ranked events.

**Tech Stack:** Python 3.12, dataclasses, SQLite-backed `ProvenanceStore`, pytest, existing NODOZE/DEPIMPACT modules.

**Spec:** `docs/superpowers/specs/2026-09-07-poi-alert-context-pruning-design.md`

## Global Constraints

- Candidate construction, scoring, and pruning must not inspect evaluation ground truth.
- Existing POI text/array/object formats and undirected diffusion remain reproducible.
- UBC12 candidate events are capped at 250,000 and the explicit window is inclusive.
- Every mandatory stage edge consumes the raw-event budget; infeasible budgets are reported explicitly.
- The project is not a Git repository, so each task ends with tests and a change review instead of a commit.

---

### Task 1: Ordered POI incident manifest

**Files:**
- Modify: `tc_pruning/poi.py`
- Modify: `tc_pruning/cli.py`
- Test: `tests/test_poi.py`
- Test: `tests/test_evaluation_cli.py`

**Interfaces:**
- Produces: `POIGroup(group_id, event_ids, window_start_ns, window_end_ns)`.
- Produces: `POIManifest(event_ids, groups)` and `load_poi_manifest(path)`.
- Consumes later: ordered group event IDs and explicit inclusive bounds.

- [ ] Write a test whose production break is collapsing explicit groups or losing stage order. Use a two-stage JSON group with literal bounds and assert the returned tuple order and bounds.
- [ ] Write a test whose production break is accepting a partial or reversed window.
- [ ] Run `python -m pytest tests/test_poi.py -q` and verify the new tests fail because `load_poi_manifest` is absent.
- [ ] Implement strict manifest parsing while retaining `load_poi_event_ids` as a compatibility projection.
- [ ] Change the experiment CLI to build one incident from legacy `event_ids` and preserve explicit groups for structured manifests.
- [ ] Run `python -m pytest tests/test_poi.py tests/test_evaluation_cli.py -q` and verify success.

### Task 2: Explicit alert windows and relation-aware seeds

**Files:**
- Modify: `tc_pruning/evaluation.py`
- Test: `tests/test_evaluation_cli.py`

**Interfaces:**
- Produces: `AttackAnnotations.seed_event_sequences` and `AttackAnnotations.investigation_windows`.
- Consumes: `POIManifest.groups` from Task 1.

- [ ] Write an integration test with background edges before and after the POI timestamps but inside explicit bounds; assert both enter the candidate graph.
- [ ] Write a test with a WRITE POI and assert the process/source, not the file/destination, is the effective diffusion seed.
- [ ] Run both tests and verify failures show timestamp-fallback and destination-only behavior.
- [ ] Parse group windows and ordered sequences in `AttackAnnotations.load`; have `run_experiment` prefer explicit windows and use `event_investigation_anchor` consistently.
- [ ] Run `python -m pytest tests/test_evaluation_cli.py -q` and verify success.

### Task 3: Time-respecting edge diffusion

**Files:**
- Modify: `tc_pruning/diffusion.py`
- Modify: `tc_pruning/config.py`
- Modify: `tc_pruning/evaluation.py`
- Test: `tests/test_diffusion_pruning.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `diffuse_importance(..., mode="time_respecting_bidir", seed_edges=...)`.
- Extends: `DiffusionResult.edge_scores` and `DiffusionResult.mode` with compatibility defaults.
- Produces: `ExperimentConfig.diffusion_mode` from optional `scoring.diffusion_mode`.

- [ ] Write a test whose production break is propagation from a late seed through a later edge in backward mode or an earlier edge in forward mode.
- [ ] Write a high-fanout test asserting a low-fanout causal bridge receives a larger edge score than a hub distractor with the same rarity.
- [ ] Write a pruning test asserting an explicit edge diffusion score is used instead of the maximum endpoint score.
- [ ] Run the three tests and verify expected failures against the undirected-only implementation.
- [ ] Implement relation-aware causal endpoints, monotonic forward/backward propagation, square-root fanout normalization, and edge-level scores.
- [ ] Add optional `scoring.diffusion_mode`, defaulting to `undirected_ppr`, and pass POI edges from evaluation.
- [ ] Run `python -m pytest tests/test_diffusion_pruning.py tests/test_config.py -q` and verify success.

### Task 4: Ordered stage backbone

**Files:**
- Modify: `tc_pruning/pruning.py`
- Modify: `tc_pruning/evaluation.py`
- Test: `tests/test_diffusion_pruning.py`
- Test: `tests/test_evaluation_cli.py`

**Interfaces:**
- Produces: `adaptive_prune(..., ordered_connectivity_edge_ids=...)`.
- Produces: ordered-stage candidate and retained connectivity counters in each result row.

- [ ] Write a four-stage graph test where the middle low-score bridges would be pruned by ranking; assert connectivity protection retains all consecutive paths.
- [ ] Write an infeasible-budget test asserting mandatory stages remain and overflow is reported.
- [ ] Write an experiment test asserting the POI sequence reaches pruning in declared order and produces stage connectivity metrics.
- [ ] Run the tests and verify failure because no ordered connectivity argument or metrics exist.
- [ ] Implement consecutive-pair time-window filtering, reuse the directed shortest-path planner per pair, and merge the resulting mandatory backbone before ranking.
- [ ] Pass ordered edge IDs from each incident through merged pruning and method-comparison rows.
- [ ] Run `python -m pytest tests/test_diffusion_pruning.py tests/test_evaluation_cli.py -q` and verify success.

### Task 5: External POIs for UBC ground truth

**Files:**
- Modify: `tc_pruning/ubc_groundtruth.py`
- Modify: `tc_pruning/cli.py`
- Test: `tests/test_ubc_groundtruth.py`

**Interfaces:**
- Extends: `prepare_ubc_manifests(..., poi_event_ids=None)`.
- Extends CLI: `prepare-ubc-annotations --poi-events PATH` for a single scenario.

- [ ] Write a synthetic UBC test with two ordered external POIs; assert seed order, one incident group, explicit scenario bounds, and paths ending at those POIs.
- [ ] Write rejection tests for missing-database and out-of-window external POIs.
- [ ] Run `python -m pytest tests/test_ubc_groundtruth.py -q` and verify the API tests fail.
- [ ] Refactor path derivation into a helper, accept validated external events, and record analyst-supplied provenance in metadata.
- [ ] Wire the optional CLI argument and reject its use with `--scenario all`.
- [ ] Run `python -m pytest tests/test_ubc_groundtruth.py tests/test_evaluation_cli.py -q` and verify success.

### Task 6: UBC12 profile, POIs, documentation, and launch

**Files:**
- Create: `configs/tc_pruning_poi_alert.json`
- Create: `poi/cadets-e3-ubc-12-pdf-stage-pois.json`
- Modify: `README.md`
- Create at launch: `scripts/run_ubc12_poi_alert_<timestamp>.sh`

**Interfaces:**
- Consumes: the manifest, window, temporal diffusion, and stage-backbone APIs from Tasks 1--5.
- Produces: regenerated UBC12 annotations, detached run script, timestamped log, progress checkpoint, and final result JSON.

- [ ] Add the seven database-verified event IDs in report order and literal scenario bounds to the POI manifest.
- [ ] Add the merged window profile with `time_respecting_bidir`, weights 0.55/0.25/0.15/0.05, 250,000 candidate limit, and 5%--50% budget curve.
- [ ] Document the manifest schema, external-POI annotation command, foreground command, detached command, and result interpretation.
- [ ] Run `python -m pytest tests -q` and require zero failures.
- [ ] Run `python -m tc_pruning.cli prepare-ubc-annotations` with the stage POIs and inspect that all seven match and every generated path ends at a selected PDF POI.
- [ ] Create a timestamped shell script using `nohup`, unbuffered Python, PID capture, and stdout/stderr redirection to a timestamped log.
- [ ] Start the script, verify the PID is alive, and inspect the initial progress checkpoint/log for the selected database, seven POIs, one incident, explicit window, and temporal diffusion profile.
