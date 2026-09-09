# POI Alert-Context Pruning Design

## Objective

Treat analyst-selected POIs as stages of one alert episode, construct the raw
event context before pruning, and then preserve a time-respecting stage
backbone while ranking the remaining events with rarity and causal diffusion.
The implementation must remain independent of evaluation ground truth during
candidate construction, scoring, and pruning.

## Evidence and problem statement

The UBC12 PDF-selected run used three correct late-stage events, but the CLI
converted them into three singleton alert groups. The default `per-alert`
scope therefore scored and pruned three copies of one incident separately.
The resulting candidate graph contained 403 of the 524 ground-truth events
that were time-respecting reachable from those POIs, but only 403 of the 5000
broad scenario events. The 5000-event label is deliberately broad: every
event inside the scenario window whose endpoints are both reviewed attack
nodes is included.

The current graph diffusion is undirected and projects a node score to an edge
with `max(src, dst)`. A high-volume process can consequently promote all of
its incident edges. At a 10% budget, the observed conditional ground-truth
recall was 36.97% for rarity alone and 1.74% for diffusion alone. In addition,
the candidate search emitted no complete evidence paths, while the configured
fusion still reserved weight for path importance. Finally, the ground-truth
`attack_paths` ended at the former automatically selected WRITE events, while
connectivity protection targeted the new PDF POIs.

Disabling search thresholds is not an acceptable fix: the diagnostic search
reached the one-million-event safety limit and the 120-second deadline before
finishing all three POIs.

## POI policy for UBC12

Use one POI for each distinct PDF-described stage and avoid repeated packet
events. All seven POIs form one ordered incident:

1. Nginx connects to loaderDrakon at `155.162.39.48:80`.
2. Nginx writes `/tmp/XIM`.
3. `/tmp/XIM` executes.
4. XIM connects to Drakon C2 `53.158.101.118:80`.
5. XIM writes `/tmp/test`.
6. `/tmp/test` executes.
7. test connects to micro C2 `192.113.144.28:80`.

The incident window is the report-defined UBC12 interval,
2018-04-12 13:59:00--14:39:00 America/New_York, represented as
`1523555940000000000--1523558340000000000` nanoseconds UTC. The database
contains 138,261 events in this interval, below the 250,000-event candidate
safety limit.

## Input model

`tc_pruning.poi.load_poi_manifest(path)` returns a `POIManifest` containing
ordered `POIGroup` values. Each JSON group has:

- `group_id`: stable incident identifier;
- `seed_event_ids`: ordered stage POIs;
- optional `window_start_ns` and `window_end_ns`: inclusive raw-event bounds.

Legacy JSON arrays, text files, and objects containing only `event_ids` stay
supported. A legacy multi-POI file becomes one `all-pois` incident by default;
callers that require separate alerts must provide explicit groups.

`AttackAnnotations` retains each group's ordered event sequence and explicit
window. For window candidate construction, explicit bounds take precedence
over a KAIROS window encoded in the group name, which takes precedence over
the minimum and maximum POI timestamps.

## Candidate construction

The UBC12 profile uses the existing `window_context` strategy. It reads the
union of all raw events in the explicit alert window with timestamp-indexed
pagination and deduplication. Evaluation labels are never consulted.

The effective diffusion seed for every POI is selected by
`event_investigation_anchor`, rather than always using the destination. This
keeps process-side anchors for WRITE, EXECUTE, and CONNECT and child/process
anchors for read-like and lineage events.

## Time-respecting diffusion

Keep the existing undirected personalized PageRank mode for reproducibility.
Add an opt-in `time_respecting_bidir` mode used by the new POI alert profile.
It performs two monotonic propagations over the candidate events:

- forward propagation starts at POI investigation anchors and only traverses
  events at or after the anchor time;
- backward propagation starts at the same anchors and only traverses events
  at or before the anchor time.

READ/receive events already carry information from object/socket to process.
EXECUTE is treated as file-to-process for propagation; other normalized CDM
edges retain their stored direction. Each transition combines rarity and
DEPIMPACT affinity and is divided by the square root of local causal fanout.
This prevents a high-degree nginx process from assigning the same score to
all adjacent events. The result records edge-level diffusion scores; pruning
uses that edge score instead of `max(src_score, dst_score)`.

## Fusion and pruning

The new profile uses merged-incident pruning and these weights:

- rarity: 0.55;
- time-respecting diffusion: 0.25;
- DEPIMPACT: 0.15;
- behavior: 0.05;
- evidence-path score: 0.00 for pure window context.

Every explicitly selected POI is mandatory. Connectivity protection also
computes a minimum-cost, time-respecting directed path between each consecutive
pair of stage POIs. The union of these POIs and bridges is the mandatory stage
backbone. All mandatory raw events count against the requested budget. If the
backbone exceeds a budget, the result retains it, marks that budget infeasible,
and reports the overflow rather than silently breaking the attack stages.

The remaining budget is filled by the fused edge score. Experiments continue
to report the full 5%--50% retention curve; the recommended operating point is
the smallest feasible budget that retains the complete POI-stage backbone.

## Evaluation

`prepare-ubc-annotations` accepts an external POI manifest for one selected
scenario. It preserves the reviewed attack nodes and broad attack events but
regenerates entry-to-POI evaluation paths with those external PDF POIs. The
manifest records that the POIs are analyst/PDF supplied and not detector
output.

Each pruning row additionally reports ordered stage connectivity: number of
adjacent stage pairs, number connected in the candidate graph, and number
still connected after pruning. This metric uses only the declared POIs and
the candidate graph, so it can be used online without evaluation-label
leakage.

## Error handling and compatibility

- Reject groups with no POIs, duplicate group IDs, partial window bounds, an
  end earlier than the start, or root `event_ids` inconsistent with groups.
- Reject an external UBC POI that is missing from the database or outside the
  scenario window.
- Keep legacy diffusion and legacy POI-file parsing behavior available for
  reproducing earlier result files.
- Preserve existing resource-limit checkpoint behavior.

## Verification

Unit tests cover manifest parsing, explicit-window precedence, relation-aware
window seeds, time direction, fanout suppression, edge-level diffusion,
ordered stage-backbone retention, infeasible-budget reporting, and external
POI path regeneration. The complete `tests` suite must pass before launch.
The final UBC12 command runs detached, writes stdout and stderr to a
date-and-time-named log, and writes the result JSON and progress checkpoint
under the PDF-reselected UBC12 output directory.
