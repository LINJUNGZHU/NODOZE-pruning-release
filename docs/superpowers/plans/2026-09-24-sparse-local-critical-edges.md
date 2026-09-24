# Local SPARSE-style Critical Edge Reference Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` to implement this plan task by task. The user has explicitly requested autonomous execution without a confirmation step.

**Goal:** Build and evaluate an auditable, event-level *local* critical-edge reference for the five specified attack cases using the SPARSE paper's POI, IOC, and attack-step procedure.

**Architecture:** Keep the existing candidate ledgers and POI decisions frozen. A review-packet extractor finds report-related CDM events and bounded temporal/causal neighbors without consulting detector decisions. A separate case-specific annotation manifest records reviewed critical event IDs, attack-stage rationale, and PDF evidence. A local-reference evaluator calculates operational proxy confusion matrices only under an explicit closed-world benchmark convention, while the existing strict evaluator continues to report official-equivalence FP/FN/Precision/Recall/F1 as unavailable. Include a leakage and uncertainty audit.

**Implementation ruling:** Annotators choose one exact exemplar event per meaningful report action. The resolver expands each exemplar to raw parallel events with identical host, directed endpoints, and relation within 10 seconds. This reflects SPARSE's parallel-edge compaction while retaining this repository's event-ID granularity. It may group extra traffic on a busy pair, so results remain a local proxy.

**Tech Stack:** Python 3, gzip JSONL ledgers, JSON manifests, pytest, local DARPA E3 report PDF.

**Spec:** User request on 2026-09-24; SPARSE §V-A2 and §IV-D, [paper](https://arxiv.org/html/2405.02629v1); existing [five-case study](../../sparse-five-case-study.md).

## Global Constraints

- Cases are Five Dir 1/3 and Theia 1/3/5 as mapped in `configs/sparse_five_cases.json`; last-case TRACE mapping remains an explicit inference.
- POIs come from report-derived evidence, without external alerts.
- Never call a proxy critical set the unpublished SPARSE ground truth.
- Record event ID, host, timestamp, relation, endpoints, stage, PDF page, and inclusion reason for each positive.
- Identify labels without consulting algorithm decisions; freeze the reference before comparing methods.
- Retain `NA` for SPARSE-equivalent metrics; name every local-reference score `proxy_*` and state its closed-world assumption.
- Do not treat a DEPIMPACT entity pair's every raw event as critical by default.

## Review Focus

- Duplicate events and parallel edges must remain distinguishable by event ID and time.
- Evidence in another host or attack date must not satisfy an IOC match.
- A nearby benign event sharing a process or socket must not become positive without an attack-stage explanation.
- Reference events outside a candidate ledger must be reported, not silently discarded.
- Detector outputs must not influence label selection.

### Task 1: Reproducible review packets

**Files:** Create `scripts/build_sparse_critical_review_packets.py`; create `tests/test_sparse_critical_review_packets.py`; write packets under `docs/sparse-five-critical-review/`.

**Interfaces:** Input case config and stage-anchor config; output JSON packets containing anchors, bounded same-host temporal neighbors, POI lineage, and the frozen ledger SHA-256. Exclude `decisions` from packet output.

- [x] Write a test with parallel and unrelated-host events; require distinct IDs and no unrelated-host neighbors.
- [x] Run the test and confirm it fails before implementation.
- [x] Implement streaming extraction and deterministic output.
- [x] Run the focused test and produce the five packets.

### Task 2: Curate event-level critical reference

**Files:** Implemented as `configs/sparse_five_local_critical_choices.json`, `docs/sparse-five-local-critical-reference.json`, `scripts/validate_sparse_local_critical_edges.py`, and `tests/test_sparse_local_critical_edges.py`.

**Interfaces:** Each positive contains its exact event ID and attack-stage rationale; validator joins it to the frozen ledger and checks host, timestamp, relation, endpoints, uniqueness, PDF page, and graph linkage. Include explicit uncertain event IDs and reasons without scoring them as positives or negatives.

- [x] Inspect official report stages and review packets, recording the exact event IDs selected for each case.
- [x] Write failing validation tests for a wrong host, duplicate ID, stale ledger hash, and unsupported stage.
- [x] Implement and run validation.
- [x] Freeze the manifest and record its SHA-256 before running any comparative score.

### Task 3: Evaluate baseline and optimized outputs

**Files:** Implemented as `scripts/evaluate_sparse_local_reference.py`, `tests/test_sparse_local_reference_evaluation.py`, `scripts/export_sparse_local_reference_csv.py`, `docs/sparse-five-local-critical-results.json`, `docs/sparse-five-local-critical-performance.csv`, and `docs/sparse-five-local-critical-study.md`.

**Interfaces:** Pair each frozen candidate ledger with baseline and optimized decisions. Report exact positive hits, stage coverage, `proxy_tp/fp/fn/tn`, `proxy_precision/recall/f1`, and the number of uncertain edges. Report separate SPARSE-equivalent metric fields as `NA`.

- [x] Write tests verifying event alignment, negative-universe convention, unknown handling, and metric arithmetic.
- [x] Run tests red, then implement minimal evaluator and run green.
- [x] Evaluate all five cases and document graph-granularity, POI, and label limitations.
- [x] Run full tests, source-hash checks, code review, and commit the auditable results.
