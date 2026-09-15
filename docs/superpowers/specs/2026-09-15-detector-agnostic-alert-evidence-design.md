# Detector-Agnostic Alert Evidence Layer — Design

**Scope:** CADETS_E3 only. ORTHRUS and KAIROS remain frozen baselines; Velox,
R-CAID, and NODLINK are added through PIDSMaker. OCR-APT is explicitly deferred
until the three mandatory detectors finish.

## Research contract

This experiment measures how useful a detector's native output is as a seed for
attack investigation, not detector classification F1. Every detector is mapped
to one immutable `AlertEvidence` contract and passed to the same reconstruction
backend, projection, partial-positive ground truth, budget, and selectors.
Candidate-ceiling results are measured before selection.

The frozen local database is
`output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db` (SHA-256
`719f97dafb642f49b0cffff6deaeb42138386521cfc2cf27539d6d5ae6a81abf`).
The implementation baseline is commit
`822e66c0bfe0c2d071f1972420612d6d8514b15e`. Existing KAIROS-MOSAIC negative
results remain unchanged and are not reinterpreted.

## Data identity

PIDSMaker's CADETS_E3 PostgreSQL database contains original `event_uuid` and
node UUIDs. Its NetworkX graphs already retain `event_uuid`, but tensorization
currently discards it. We will propagate an event-identity vector alongside
each edge through conversion, batching, slicing, and inference. Node integer IDs
will be converted through a frozen database-derived ID-to-UUID map. Velox output
must therefore bind scores to original events directly; tuple/timestamp matching
is not an accepted primary mapping path.

When PIDSMaker fuses consecutive same-type edges, the exported identity is the
representative original event selected by the existing algorithm. The audit must
state this preprocessing reduction separately from inference mapping. No missing,
duplicate, or ambiguous identity may be silently discarded.

## Evidence contract

`AlertEvidence` contains detector/evidence identity, a real granularity enum,
raw and calibrated scores, native decision, optional event/node/src/dst/relation
and time identity, role hint, supporting events, structural context, mapping
quality, and detector metadata. It validates granularity-specific minimum fields,
finite score/range invariants, and canonical deterministic serialization.

Adapters are pure translators and may not read ground truth. Unknown roles remain
observations. Velox produces edge evidence from per-edge loss. R-CAID produces
node evidence from the node loss actually emitted by PIDSMaker; root-cause
metadata is absent unless explicitly present in a native artifact. NODLINK first
produces node evidence. A structural graph is emitted only if the implementation
actually constructs one; otherwise the report records that the PIDSMaker port is
only the screening/reconstruction-score component and does not invent Steiner
output. ORTHRUS and KAIROS get compatibility providers without changing frozen
baseline semantics.

Calibration is empirical development-set rank/percentile calibration with a
stable tie rule. It stores continuous score, native decision, development
percentile, and query/day-local percentile. Test ground truth and attack windows
are forbidden inputs.

## Candidate reconstruction

`EvidenceDrivenCandidateBuilder` is detector-name blind and always searches the
local full provenance graph. Event/edge evidence anchors both endpoints; node
evidence anchors that node; subgraph/structural evidence keeps its real members
as a soft seed region. `UNKNOWN` and `OBSERVATION` launch both strict-temporal
backward and forward search and never become an automatic source or terminal.

The first version reuses reliable V4 semantics: strict temporal traversal,
bounded control lineage/common cause, and raw-event replay. Detector score,
A_rasp contrast, rarity, temporal distance, and fanout only order the queue; a
low score is not a hard exclusion. All runs use one fixed candidate cap and the
same edge projection.

## Evaluation and fusion

For each known PDF critical edge, the offline-only funnel records: raw database,
detector preprocessing, inference graph, scored, native threshold, evidence,
candidate, and final. The online adapter/builder has no import or parameter path
to any ground-truth module or attack window.

Single-detector runs precede pairwise runs. Pairwise reports list new critical
edges, new attack nodes, projected-edge delta, and raw-event delta. Fusion is
only admitted if candidate critical-edge recall improves. Scores use development
percentile calibration and Noisy-OR on the same underlying evidence object.
Causal agreement is implemented and tested as a reliability prior only, but is
run as an experiment only after Noisy-OR has independent gain; it cannot create
provenance nodes or edges.

All detectors use A_rasp legacy as primary selector and C_branch_fair as the
secondary controlled selector. Failed KAIROS-MOSAIC S2–S5 selectors are excluded.
The partial-positive GT vocabulary is `known_TP`, `known_FN`, `known_recall`, and
`unlabeled_output_edges`; precision/FP/FPR are not claimed.

## Artifacts and admission

Each run saves native detector output, normalized evidence, identity audit,
candidate output, final output, funnel, timing, RSS, configuration, and hashes.
Detector inference time and post-alert investigation phases are reported
separately; training time is never included in online latency.

If a mandatory detector cannot complete, the report must name the exact failed
stage and preserve partial artifacts. Missing results are `NOT_COMPLETED`, never
zero. The final report is `docs/multi-detector-seed-utility-results.md` and must
answer every question in the supplied specification with measured numbers or an
explicit non-completion reason.
