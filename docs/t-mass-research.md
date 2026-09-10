# T-MASS v1: stratified mass thresholds and temporal witnesses

Status: experimental offline selector on PS-RDP score ledgers. This is an
original engineering combination in this repository, **not a claim of novel
prior-art-free research, calibrated risk control, or top-conference readiness**.

## Research basis

- [DEPIMPACT, USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/fang):
  discriminative dependency weights, backward impact propagation and forward
  causality filtering. We borrow the motivation to make causal structure an
  explicit selection concern; we do not reproduce its published performance.
- [NodLink, NDSS 2024](https://arxiv.org/html/2311.02331v1):
  models concise anomaly connection as a Steiner-tree problem and uses learned
  terminal identification. We borrow the separation of suspicious terminals
  from connecting structure, not its approximation theorem or VAE.
- [Kairos, IEEE S&P 2024](https://arxiv.org/html/2308.05034v1):
  temporal graph learning provides event-level anomaly evidence and subsequent
  investigation constructs summary graphs. Our current scorer is heuristic,
  not Kairos's learned reconstruction loss.

## Method

1. Reuse complete, frozen PS-RDP rarity/diffusion fusion scores `s(e) >= 0`.
   No retraining or new POIs in this experiment isolates selector effects.
2. Partition events into disjoint strata by winning POI, source type, relation
   and target type. This prevents a high-mass behavior class from consuming the
   entire selection while a small class disappears.
3. Protect declared POI events. Within each stratum g, select the descending
   score prefix needed to satisfy
   `sum(selected scores in g) >= (1-epsilon) * sum(all scores in g)`.
   Protected mass is credited first. Zero-score edges are not budget filler.
   Presets are epsilon = 0.05, 0.10, 0.20; the published UI preset is 0.10,
   fixed before evaluating attack truth. No target edge ratio is imposed.
4. Reverse-scan event time. An event has a witness if it is a POI or its target
   is the source of a strictly later event that already has a POI witness.
   Equal-time batches are isolated. Store one successor per reachable event.
5. Union every selected event's witness suffix, even if connectors have low
   scores. With optional `--preserve-cdm-atomicity`, also keep together CDM
   secondary edges sharing an original UUID and iterate to a fixed point.
   This option is OFF by default to compare individual directed edges on the
   baseline's counting unit. Synthetic `LINEAGE:*` IDs are never grouped merely
   because of a common textual prefix.

The pre-closure selector minimizes additional edge count independently within
each disjoint stratum under this score-mass constraint (exchange argument:
replacing a selected lower score with an unselected higher score cannot reduce
mass). **No such optimality is claimed after temporal/atomic closure.**
Sorting costs O(E log E); witness construction scans E events after sorting.
Each witness-union pass is O(E). Optional joint fixed-point closure can require
multiple passes; no linear bound is claimed for the complete algorithm.

## Guarantees and limits

- Guarantees preservation of the chosen strict-time witness for retained
  reachable events, and the stated heuristic score mass. Neither is a guarantee
  that every attack path is found, or that 10% mass loss means 10% attack loss.
- Unreachable events can still be retained by mass selection and are reported.
- A witness is a graph-level dependency, not proof that the flow was malicious.
  Shared resources/processes can still introduce irrelevant dependencies.
- Equal-time real dependencies can be missed. Forward descendants after the
  last POI do not have backward-to-POI witnesses. Future work needs richer
  event-order semantics and bidirectional temporal connectors.
- Original CDM-event atomicity is not the previous DEPIMPACT merged-edge
  grouping. Prefix-stability constraints are not imposed by this selector.
- The POIs are report-informed; this is an assisted investigation experiment,
  not automatic alert detection. Existing short reference paths and derived
  event truth cannot establish full campaign reconstruction.
- Ground truth is opened only after all selection masks are computed. Tests
  mutate truth and require byte-identical decisions. Scores and upstream POI
  provenance still need independent leakage auditing for publication.
- Replay timing excludes original ingestion and scoring. Unlabeled retained
  events are not automatically false positives. Different retention rates are
  not same-budget comparisons, and published paper numbers are not reruns.

## Reproduce

```bash
cd /root/NODOZE-pruning-release
python -u -m scripts.run_adaptive_mass \
  --ledger output/tc/theia-case3-poi-prefix-fixed-2026-09-09_23-36-33/scenario-theia-case3/poi-prefix-3-ledger/edge-scores.jsonl.gz \
  --reference output/tc/theia-case3-poi-prefix-fixed-2026-09-09_23-36-33/scenario-theia-case3/fixed-reference.json \
  --output output/tc/t-mass-NEW_TIMESTAMP \
  --cache webapp/runtime/theia-case3-demo.json
```

Use a fresh output directory. `--cache` is optional: selection never uses the
display sample. It only attaches primary decisions to the existing UI sample
and computes its complete reference-context counts for display, not selection.
The original baseline decisions remain intact in the cache. Refresh the page
and switch algorithms after completion. Output contains `comparison.json`,
`thresholds.json`, and complete `adaptive-decisions.jsonl.gz` with all presets,
score, group, reachability and witness successor for every event.

## Required next research stages

Independent days/hosts, normal-only training/calibration splits if adding ML,
fixed validation parameters, multi-POI sweeps, missing/noisy POI robustness,
manual multi-stage attack references, budget-matched and recall-matched
tradeoff curves, independent DEPIMPACT/NodLink/Kairos artifact runs, several
random seeds where applicable, end-to-end RSS/runtime, and leakage auditing.
Deep learning should only be added with a clean training protocol and measured
benefit; a larger model alone is not a research contribution.

## v1 negative result and v2 revision

On THEIA Case 3 (1,132,218 candidates, 3 fixed POIs), v1 epsilon=0.10
retained 951,706 edges (15.94% compression) and recovered 60.57% of the
derived attack events. The existing baseline retained 226,443 (80% compression)
with 76.32% recall. Both kept 3/3 short reference paths. v1 is worse; it is
retained as a negative result, not promoted as an improvement.

Why: per-stratum quotas spend space even on weak, flat-score classes, while
the latest-event witness may follow unnecessarily long chains.

Further audit found that compulsory CDM secondary-edge expansion was a major
source of the v1 blow-up, as it changed the baseline's directed-edge selection
unit. The early v1 run also incorrectly grouped synthetic `LINEAGE:*` IDs by
prefix. Those exploratory results are not a clean selector comparison. The
corrected version makes CDM atomicity optional and recognizes UUID suffixes
only; current comparisons use individual directed edges without atomic expansion.

`--mixture` implements the v2 research alternative:

1. Fit a deterministic two-component Gaussian mixture to log positive scores
   using EM (maximum 60 iterations, variance floor 1e-4). BIC must prefer two
   components over a one-component model; otherwise abstain from score-based
   expansion (keep POIs and their required original-event groups).
2. Use high-mean-component membership, also requiring log score above the
   midpoint of fitted means. Preset cutoffs 0.5/0.9/0.99 are evaluated; 0.9
   is the preselected UI preset, not chosen for attack recall. These values
   describe score-cluster membership, **not malicious probability**. This is
   transductive unsupervised fitting on the candidate graph, not normal-only
   training or a calibrated false-positive controller.
3. Keep the minimum-hop strictly later witness instead of the latest witness.
   The reverse-time DP chooses the reachable successor of minimum depth. This
   minimizes each individual witness length; it does not minimize the union.

The mass-only and T-MASS mass presets remain as ablations; in a v2 run all
closure variants use the new minimum-hop connector. `broken_selected_witness_links`
is checked to be zero for every closure variant. A witness still need not be
the true attack path. Add `--mixture` to the command above to reproduce v2.

`baseline_witness_repair` is an additional conservative alternative: it retains
the existing PS-RDP selection and only adds missing minimum-hop witness suffixes.
It does not impose mixture or mass thresholds and cannot lose previously retained
events. An independent reverse-time reachability audit on each retained subgraph
reports `lost_retained_poi_connections`, since a missing *chosen* witness link
does not imply that every alternate connection is missing.

## Audited THEIA Case 3 results (2026-09-10)

Run: `output/tc/t-mass-v2-audit-2026-09-10_12-53-40`.
Same 1,132,218 directed candidate edges, same 3 POIs and frozen importance
scores, 870 derived labeled attack events, 3 short reference paths.

| Method | Retained edges | Compression | Attack-event recall | Reference paths | Lost retained POI connections |
|---|---:|---:|---:|---:|---:|
| Existing PS-RDP | 226,443 | 80.0001% | 76.3218% | 3/3 | 1,486 |
| PS-RDP + minimum-hop repair | 226,800 | 79.9685% | 76.3218% | 3/3 | 0 |
| Mixture + witness, cutoff 0.9 | 585,395 | 48.2966% | 76.0920% | 3/3 | 0 |

The useful result is **structural repair**, not higher attack recall: 357 added
edges restore the 1,486 previously retained events' lost strict-time connections
to a POI. These are graph-level connections, not 1,486 labeled attack paths.
The mixture does not beat the baseline. No claim of same-budget superiority or
full attack reconstruction follows. The UI keeps the original baseline as its
default and offers repair and mixture as explicit alternatives.

Load, selection and independent reachability/evaluation took about 64.81 seconds
with peak RSS about 393.35 MiB on this server. This is one offline replay and
excludes original ingest/scoring and final compressed-decision export. It is
not comparable to published end-to-end system timings. All 15 presets/ablations
and per-event decisions are saved locally; data and ledgers are not uploaded.
