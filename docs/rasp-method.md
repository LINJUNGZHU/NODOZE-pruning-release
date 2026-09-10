# RASP: rarity-aware contrastive propagation and causal-fork pruning

RASP replaces the score propagation and selection stages; it is **not** another
threshold on PS-RDP's old scores. This is an experimental method developed on
THEIA Case 3 and three CADETS cases. It is not an established state-of-the-art
system, a claim of publication novelty, or proof of full attack reconstruction.

## Why the previous change failed

T-MASS operated on old scores. Per-class score-mass quotas preserved flat-score
background classes, and an uncalibrated two-Gaussian score model did not recover
attack semantics. The original temporal scorer also multiplies an edge's signal
by inverse square-root **raw event degree** at every step. Duplicate ordinary
I/O can therefore dilute the same process's important dependencies. Changing a
threshold cannot recover the propagation evidence lost upstream.

## Research connections, not imported performance claims

- [Predict then Propagate, ICLR 2019](https://arxiv.org/abs/1810.05997):
  motivates personalized restart propagation and separating propagation from
  the source of evidence. We use historical rarity and analyst POIs, not its
  trained neural predictor or semi-supervised classification protocol.
- [Diffusion Improves Graph Learning, NeurIPS 2019](https://proceedings.neurips.cc/paper/2019/hash/23c894276a2c5a16470e6a31f4618d73-Abstract.html):
  motivates localized diffusion followed by sparsification. Our auxiliary
  interaction graph supports propagation; retained evidence remains original
  events, not newly invented diffusion edges.
- [Graph Sparsification by Effective Resistances, STOC 2008 / SIAM J. Computing](https://arxiv.org/abs/0803.0929):
  motivates preserving structure, not simply deleting every low-weight edge.
  Its undirected spectral guarantees do **not** imply preservation of directed
  temporal attack paths, so RASP does not claim those guarantees or apply
  resistance sampling as a substitute for temporal evidence.
- [Local Higher-Order Graph Clustering, KDD 2017](https://doi.org/10.1145/3097983.3098069):
  motivates considering structures larger than individual edges. Our relevant
  structure is a common-cause fork, not that paper's motif-conductance algorithm.
- [SPARSE](https://arxiv.org/html/2405.02629v1):
  motivates contextual data/control-flow investigation and avoiding independent
  edge-anomaly decisions. We do not reproduce its published results.

## Inputs and isolation

Use the frozen candidate graph, existing report-informed POI event IDs, and
historical rarity from the complete ledger. Filenames, malicious IP strings,
attack-event labels, reference paths and old selection decisions do not enter
the new scorer. Old scores are loaded only for explicitly named baselines.
After **all** method masks are fixed, open the reference file to evaluate.
Tests change both ground truth and old rankings and require unchanged RASP
scores and selections. This does not undo upstream report-informed POI choice:
the task is assisted investigation, not automatic attack detection.

## Algorithm

### 1. Duplicate-invariant interaction graph

Construct one auxiliary undirected channel for each unordered endpoint pair
and relation. Its conductance is `w = 0.2 + 0.8 * max(rarity)` over its events.
Repeating an identical interaction does not increase this conductance. This
invariance holds for fixed rarity evidence; it is not a claim that arbitrary
log injection cannot alter a newly computed frequency profile.

### 2. Background-contrasted restart propagation

For each POI, place half the restart mass on each endpoint. With transition P,
compute `p_next = alpha * seed + (1-alpha) * P^T * p`, alpha=0.15. Dangling mass
returns to the restart distribution. Separately compute background q with
restart uniformly over process nodes (all nodes only if types are unavailable).
The background is graph-derived, **not a known-clean learned distribution**.

Let `L_p(v) = log(1 + max(p(v)/q(v)-1, 0))`. For event e=(u,v),
`C_p(e) = sqrt(L_p(u)*L_p(v)) * (0.2+0.8*rarity(e))`.
Normalize each POI-local C by its maximum and take the maximum across POIs.
This suppresses structural hubs that are important even without this POI.

Hard-zeroing background-common edges can eliminate necessary explanations.
Keep a weak escape channel `U_p(e) = sqrt(p(u)*p(v)) * (0.2+0.8*rarity(e))`,
also normalized per POI then aggregated by max. Final score is
`S(e) = (max_p C_p(e) + 1e-6 * max_p U_p(e)) / (1+1e-6)`.
POI scores are fixed at one. The escape channel is deliberately weak: it
provides a secondary ranking for otherwise zeroed events, not a new alarm.
All quantities are heuristic importance scores, **not attack probabilities**.

### 3. Common-cause temporal fork

Direct forward/backward paths from an alert miss sibling actions caused by
the same compromised process. Reverse-time DP first builds minimal-hop witnesses
to a POI endpoint. A forward-time DP can start at a witnessed ancestor (pivot)
and follow a different causal branch. Keep the branch to the alert and the
branch to the scored event together.

Each branch must respect directed information flow and strictly increasing
timestamps. Equal-time events never feed each other. A POI exposes both endpoint
states; a pivot exposes its source state and its output. Intermediate forward
steps follow source -> destination only. EXECUTE is oriented executable ->
process, matching the main scorer's CDM convention. The raw event is unchanged.
This is a common-cause fork, **not one monotone sequence through both branches**.

### 4. Budget-aware bundle admission

Start with POIs. Visit candidate anchors by score (deterministic SHA-256 ID tie
break). Admit an anchor only with its complete fork witness, charging each newly
retained original edge once. Skip bundles that would exceed `floor(E * budget)`.
No post-hoc edge append exceeds the cap. A retained connector can have a very low
score. Budget infeasibility for mandatory POIs raises an error, not an overflow.

The construction preserves the selected witnesses and the hard cap. It does not
prove minimum graph size, globally optimal bundle selection, all attack paths,
or any false-negative-rate bound. Its independently checked guarantee is that
retained reachable events do not lose all their anchored fork connections.

## Evaluation design and limitations

- Frozen configuration: `configs/rasp_v1.json`, copied into every output. Restart
  0.15, up to 200 iterations, L1 residual target 1e-10; all diagnostics exported.
- Budgets 1%, 5%, 10%, 20%; compare old score ranking, new ranking without path
  selection, direct-path packing, fork packing, no rarity, no contrast and hard
  contrast without an escape channel. Original PS-RDP decisions are available
  at 20% only; the other old-score rows are ranking baselines, not full PS-RDP
  reruns at those budgets.
- Same candidate graph, same POIs and same budget cap in each comparison. Raw
  directed events, not auxiliary channels, are the pruning/counting unit.
- Both reference event recall and reference-path retention matter. The reference
  paths are short derived paths, not complete multi-stage campaigns. CADETS-12's
  5,000 labeled events must not be described as 5,000 independent attack paths.
- These cases informed development, including the fork and escape-channel
  revisions. They are **not held-out tests**. Cross-host/day held-out evaluation,
  noisy/missing POI robustness, repeated independent runs, end-to-end ingestion
  timing, and independent external baselines are still required for a paper.
- Rarity ablations may leave event recall unchanged while changing connector
  cost or reference-path preservation; do not claim uniform gains for every
  component. A positive result on four cases is not a top-conference result.
- Timings here include frozen-ledger loading, new scoring, selection and
  reachability audits, but exclude initial ingestion/frequency estimation and
  final compressed export. Do not compare them with published end-to-end times.
- Pure contrast and strict direct-path versions are saved as negative/ablation
  results. They are not silently deleted when the final method improves.

## Run and inspect

```bash
cd /root/NODOZE-pruning-release
python -u -m scripts.run_rasp \
  --ledger output/tc/theia-case3-poi-prefix-fixed-2026-09-09_23-36-33/scenario-theia-case3/poi-prefix-3-ledger/edge-scores.jsonl.gz \
  --reference output/tc/theia-case3-poi-prefix-fixed-2026-09-09_23-36-33/scenario-theia-case3/fixed-reference.json \
  --output output/tc/rasp-NEW_TIMESTAMP \
  --cache webapp/runtime/theia-case3-demo.json

python -u -m scripts.run_rasp_suite --output output/tc/rasp-cadets-NEW_TIMESTAMP
python -m webapp.scripts.publish_rasp_validation \
  --suite output/tc/rasp-cadets-NEW_TIMESTAMP/suite.json
```

Use new output directories. For background execution, redirect stdout/stderr to
`logs/rasp-YYYY-MM-DD_HH-MM-SS.log` and use nohup or a service manager.
`comparison.json`, configuration and implementation hashes, convergence
diagnostics, and the complete `rasp-edge-scores.jsonl.gz` stay on the server.
Every event gets its new score, rarity, contrast evidence, POI provenance,
fork pivot/links, and each budget's keep/delete decision.

The UI can switch old/new algorithms and RASP budgets; the **same display sample**
is used on both sides. Scores and decisions change together, and all complete
experiment metrics remain separate from sample-level graph counts. CADETS
validation tables do not turn the THEIA graph into a CADETS visualization.

## Audited results, 2026-09-10

Outputs: `rasp-theia-audit-2026-09-10_13-24-26` and
`rasp-cadets-audit-2026-09-10_13-24-26` under `output/tc/`.
All personalized and background propagations met the configured residual target.

The following rows all retain the **same number of edges as their baseline**
(20% of their respective frozen candidate graphs, rounded down):

| Case | Retained edges, both methods | PS-RDP event recall | RASP event recall | PS-RDP / RASP reference paths |
|---|---:|---:|---:|---:|
| THEIA Case 3 | 226,443 | 76.3218% | 98.8506% | 3/3 → 3/3 |
| CADETS-06 | 20,446 | 98.5075% | 100.0000% | 3/3 → 3/3 |
| CADETS-12 | 27,652 | 8.3000% | 99.1200% | 8/8 → 8/8 |
| CADETS-13 | 7,193 | 75.7028% | 82.7309% | 3/3 → 3/3 |

At 10% budget THEIA retains 113,221 edges with 98.8506% event recall and 3/3
references. **This is not a universally safe budget**: CADETS-12 falls to
15.44% event recall and 3/8 references at 10%. The UI therefore defaults to
the predeclared 20% preset, not a per-case ground-truth-optimized budget.

The four replay timings (load + new scoring + selection/audits, before export)
were approximately 93.17, 6.91, 10.74 and 2.42 seconds. Peak RSS was 588.43,
88.18, 107.44 and 55.14 MiB, respectively. These are single-run engineering
measurements, not statistical performance claims or end-to-end ingest timings.

Twenty configurations/budget/ablation rows are retained per case. In particular,
hard contrast with no weak escape channel lost CADETS-12 reference paths; pure
uncorrected PPR underperformed badly on THEIA. Removing rarity did not change
THEIA event recall but increased connector cost; in CADETS-12 it lost reference
paths. These observations explain the design revisions but are still development
evidence, requiring held-out testing before claiming a general research advance.
