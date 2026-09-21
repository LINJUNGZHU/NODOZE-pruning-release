# KAIROS K6 POI-Conditioned Context Evaluation Design

## Goal

Use the label-free KAIROS-MOSAIC K6 expansion as the alert source, derive
evaluation-only POIs from the K6 endpoints that overlap ORTHRUS node positives,
reconstruct a common context around those POIs from the complete frozen
database, and compare A_rasp with C_branch_fair without charging either
selector for an attack path that is unrelated to its POIs.

## Experimental boundary

The online K6 artifacts are frozen before ORTHRUS is loaded. ORTHRUS is used
only by the offline experiment to identify which K6 endpoint nodes are known
attack nodes and to score the frozen selector outputs. This is an
oracle-assisted POI study, not a deployable detector pipeline and not an
unbiased detector comparison.

The experiment covers CADETS E3 scenarios 06, 12, and 13. Scenario 11 remains
outside the frozen experimental scope. Per-scenario ORTHRUS denominators are
8, 43, and 24 node annotations; cross-scenario reporting also deduplicates the
three nodes shared by scenarios 12 and 13.

## Data flow

1. Verify and load one frozen Track-B KAIROS online artifact per scenario.
2. Read K6 event IDs and resolve their exact stored edges in the frozen CADETS
   E3 database.
3. Intersect K6 edge endpoints with the scenario's ORTHRUS node positives.
   The intersection is the evaluation-only POI set.
4. Convert POI nodes to node-granularity evidence and reconstruct one common
   context from the complete frozen DB with `EvidenceDrivenCandidateBuilder`.
5. Choose one deterministic incident candidate event per POI as an edge proxy.
   Prefer overlap with the lowest KAIROS layer, then timestamp and event ID.
6. Apply A_rasp and C_branch_fair to the same candidate, proxy set, and absolute
   raw-event budget.
7. Freeze both selections, then evaluate them against POI-scoped ORTHRUS paths.

## POI-scoped oracle

Strict temporal paths are derived from the common reconstructed candidate using the existing
earliest-arrival rule. A path is eligible only when at least one endpoint is a
K6-derived POI node. Paths between two non-POI attack nodes are excluded from
all denominators.

Eligible paths are divided into:

- `backward_path`: a non-POI attack node reaches a POI;
- `forward_path`: a POI reaches a non-POI attack node;
- `poi_to_poi_path`: one POI reaches another POI;
- `anomaly_path`: the union of the three POI-touching families;
- `time_path`: anomaly paths stratified by elapsed interval and path length;
- `anomaly_time`: exact canonical retention and alternative strict-temporal
  reachability reported together for each interval/length cell.

Each path record contains source, target, ordered event IDs, elapsed
nanoseconds, and path length. Empty path families are reported as N/A rather
than perfect recall.

## CONTEXTS-aligned reporting

CONTEXTS evaluates output subgraphs using reference-subgraph TP/TPR, FP/FPR,
graph size, and processing time, and studies backward/forward, path-anomaly,
path-time, and joint anomaly-time pruning. Our report uses the corresponding
quantities that the available labels support:

- POI-local reference node/event/path counts;
- candidate and final TP/TPR;
- canonical complete-path retention;
- strict-temporal reachability retention;
- backward and forward path retention;
- interval buckets: `<=1m`, `<=10m`, `<=1h`, `<=6h`, `<=1d`, `>1d`;
- path-length buckets: `1-2`, `3-5`, `6-10`, `>10`;
- raw events, projected edges, elapsed time, and peak RSS;
- `unlabeled_output_edges`, explicitly not called false positives.

ORTHRUS supplies partial-positive node labels and no exhaustive normal-edge
labels. Consequently precision, FP, FPR, and F1 are `NOT_AVAILABLE` rather
than inferred from the unlabeled complement.

## Failure handling and reproducibility

The run fails closed when an online artifact is incomplete, a K6 event is
missing from the database, no POI is recovered, the selector exceeds its
budget, or input hashes change. The result records all input hashes, the
database identity, configuration, per-stage timings, and a content hash.

## Tests

Synthetic tests prove that unrelated attack paths are excluded, backward and
forward paths are separated, exact path and alternative reachability differ,
time/length cells use hand-checked denominators, empty cells are N/A, and one
proxy is selected per POI. An integration fixture runs both selectors against
the same reconstructed candidate and checks budget and truth-isolation contracts.
