# CONTEXTS Native-POI A_rasp-PBR Experiment Design

## Goal

Run `A_rasp`, `A_rasp-PBR`, and `C_branch_fair` on all 20 scenarios in the
official CONTEXTS kernel-exploit dataset. Prefer dataset-native investigation
anchors and invoke KAIROS only when a scenario has no native `POI`, `WP1`, or
`WP2` node.

## Inputs and identity

- Dataset: Zenodo record `15200286`, publication date 2025-04-11.
- Archive: `/root/CONTEXTS-DATASET.zip`, MD5
  `e0bfc9990f02378f9c0f0fc5d3e8668d`.
- Each scenario contains one Neo4j dump and one `query.cypher`.
- The supplied `/root/README.md` is an HTTP 404 JSON, so the published Zenodo
  metadata and the archive contents are the authoritative description.
- Native online labels: `POI`, `WP1`, and `WP2`. Offline-only labels: `GT`.

## Isolation contract

Online selection reads node/edge properties and native POI/waypoint labels. It
must not read `GT`, execute the ground-truth query, or inspect offline metrics.
The online artifact is hashed and sealed before an offline evaluator receives
the GT node set. Every scenario records `poi_source`; `dataset_native` is
mandatory when any native anchor exists. `kairos_fallback` is permitted only
when the native anchor set is empty. The present archive has native anchors, so
no KAIROS artifact should be loaded by the formal run.

## Neo4j extraction

The dumps use Neo4j 4.3 record format inside Neo4j ZSTD archives. Restore with
Neo4j Community 5.26.4, then migrate with
`--force-btree-indexes-to-range`. Export nodes and relationships over the local
Bolt/HTTP interface. Stable local identities are `contexts:<scenario>:node:<id>`
and `contexts:<scenario>:rel:<id>`; the original Neo4j IDs and properties remain
in the export for audit.

SPADE relations map to the common causal model as follows:

| SPADE relation | Causal direction | Canonical relation |
|---|---|---|
| `Used` | artifact → process | `EVENT_READ` |
| `WasGeneratedBy` | process → artifact | `EVENT_WRITE` |
| `WasTriggeredBy` | parent process → child process | `EVENT_FORK` |
| `WasDerivedFrom` | source artifact → derived artifact | `EVENT_DERIVE` |

Decimal second timestamps are converted to integer nanoseconds without
floating-point arithmetic. Process, file, memory, pipe, and unknown node types
are retained explicitly.

## Candidate and selectors

CONTEXTS states that every supplied graph has already undergone its Initial
Pruning step. Therefore the full restored scenario graph is the common
candidate; no KAIROS-driven candidate retrieval is applied. Each native anchor
gets one deterministic incident-event proxy, selected without GT. The maximum
raw-event budget is `min(8000, candidate_edges)`.

- `A_rasp` reuses the unchanged selector. Because the archive contains no
  separate benign-history corpus, rarity is a label-free scenario-local
  frequency proxy and must be reported as such.
- `A_rasp-PBR` runs after frozen A_rasp with a `+50%` rescue ratio, maximum
  1,000 additional raw events, K=3 strict paths, and no GT access.
- `C_branch_fair` uses the same mandatory proxies and maximum budget. Branch
  provenance is derived from strict forward/backward reachability of native
  anchors and native waypoint roles.

## Offline evaluation

A GT edge is a candidate relationship whose two endpoints are both `GT`
nodes. Report output graph size, GT-edge TP/FN/recall, output non-GT edge count
(descriptive, not a proven FP), GT-node recall, strict temporal path retention,
POI/waypoint-to-POI/waypoint retention, backward and forward retention, time and
path-length buckets, selector time, and peak RSS. Precision/FPR/F1 are not
claimed because `GT` is a positive subgraph annotation rather than a complete
normal-edge label set.

## Outputs

Write immutable inputs, per-scenario online artifacts, online seal, per-scenario
offline metrics, aggregate comparison, progress, process status, log, and a
Markdown report under `output/contexts-native-poi-pbr-runs/<run-id>/`.

The run may skip a scenario only with an explicit `NOT_COMPLETED` reason. A
formal aggregate is `COMPLETED` only when all 20 scenarios complete.

