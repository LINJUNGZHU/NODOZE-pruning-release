# Detector-Agnostic Alert Evidence Layer Implementation Plan

**Spec:** `docs/superpowers/specs/2026-09-15-detector-agnostic-alert-evidence-design.md`

**Goal:** Run a CADETS_E3 seed-utility comparison for ORTHRUS, KAIROS, Velox,
R-CAID, and NODLINK using identity-preserving detector output and one common
candidate/pruning backend.

**Global constraints:** Preserve all unrelated dirty work. Never read test GT,
PDF edges, attack timestamps, or funnel data in adapters, calibration, fusion,
candidate search, or stopping. Do not fabricate detector fields. All detector
runs share the same candidate configuration, projection, budgets, and selectors.
Use only partial-positive terminology. Save intermediate artifacts and distinguish
`NOT_COMPLETED` from zero. Implement with tests first and commit only task-owned
files.

## Task 1: PIDSMaker identity-preserving native exports

Modify the tracked PIDSMaker checkout under
`webapp/runtime/research/PIDSMaker` so edge event UUIDs and node UUIDs survive
graph conversion, tensorization, batching, slicing, and inference export. Export
continuous losses and identity fields for Velox and node IDs for R-CAID/NODLINK.
Add PIDSMaker tests for event identity, score columns, node identity, ordering,
and fused-edge representative semantics. Run its focused tests and record its
separate nested-repository commit.

## Task 2: Evidence, adapters, calibration, and fusion

Create the typed `AlertEvidence` contract, JSONL serialization, base provider,
Velox/R-CAID/NODLINK adapters, ORTHRUS/KAIROS compatibility providers,
deterministic development calibration, Noisy-OR, and causal-agreement primitives.
Write failing tests for validation, no fabricated root metadata, threshold
consistency, deterministic ties, same-object fusion, GT isolation, and agreement
not creating graph facts; then implement and run them.

## Task 3: Common candidate engine and evaluation

Implement a detector-name-blind evidence candidate builder on `G_full`, using
strict backward/forward temporal traversal for unknown observations and existing
V4/control semantics. Add seed-utility, coverage-funnel, complementarity, and
performance metrics. Test all evidence granularities, unknown-role directionality,
candidate ceiling decomposition, pairwise deltas, common configuration enforcement,
and legacy compatibility.

## Task 4: Experiment runner and configuration

Add a CADETS_E3-only benchmark configuration and scripts that persist native,
evidence, audit, candidate, final, funnel, configuration/hash, and timing/RSS
artifacts. Add validation preventing detector-specific candidate backends and GT
paths in online inputs. Test a miniature end-to-end fixture before full runs.

## Task 5: Mandatory detector execution

Freeze hashes and reproduce current ORTHRUS/KAIROS baselines. Run PIDSMaker
Velox, then R-CAID, then NODLINK on the existing CADETS_E3 PostgreSQL database.
For Velox run VXL-0 through VXL-3 as specified. Preserve logs and partial outputs
if a stage fails. Normalize each detector and run the identical common candidate
backend before any fusion.

## Task 6: Controlled comparisons and final report

Generate single-detector tables/frontiers and coverage funnels. Run required
pairwise complementarity. Admit Noisy-OR only for pairs with independent candidate
recall gain; run causal agreement only if Noisy-OR gains. Run A_rasp primary and
C_branch_fair secondary on the fixed candidates. Generate the 25-section report
at `docs/multi-detector-seed-utility-results.md`, including native/mapped/candidate
identity decomposition, runtime/RSS, negative results, and one evidence-backed
final detector or detector-pair recommendation.

## Task 7: Verification and review

Run focused tests, PIDSMaker tests, the full `PYTHONPATH=. python -m pytest -q`
suite, artifact consistency checks, GT-import scans, deterministic reruns, and
hash checks. Review all implementation/report claims against saved artifacts and
record any rulings or non-completed stages explicitly.
