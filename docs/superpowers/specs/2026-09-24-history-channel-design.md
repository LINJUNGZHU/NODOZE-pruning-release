# Historical conditional frequency and channel retrieval (v6)

User requests autonomous implementation of the previously identified bottleneck.
Keep the frequency-statistics + graph-diffusion architecture and all five frozen
candidate ledgers/POIs. No external alert or evaluation-label input to selection.
These are inspected development cases, not a held-out generalization claim.

## Fixed design before outputs
1. Build conditional semantic frequencies from each case's existing SQLite DB,
   read-only. Relative to earliest declared POI in the original full scenario:
   fit window [POI-24h, POI-60min), calibration [POI-60min, POI-30min).
   Cutoffs stay fixed under POI deletion. Counts are occupied 60-second buckets
   per (host, src semantic/type, relation, dst semantic/type), not raw duplicates.
   Snapshot node metadata can include later updates; these are historical edges
   with existing snapshot semantics, NOT a verified benign or strictly online fit.
2. Hierarchical smoothing: conditional probability of destination semantic/type
   given source semantic/type and host/relation, backed off to destination
   frequency within host/relation. Dirichlet strength 10, Laplace destination
   smoothing 1 including one unseen category. Novelty = -log(probability).
3. Weighted midrank ECDF of calibration novelty within host/relation; no attack
   labels. Require at least 32 occupied buckets in BOTH fit and calibration.
   Otherwise preserve original rarity. Mix original rarity and ECDF 50/50;
   feed the result into the unchanged frequency diffusion engine and existing
   300-second temporal rerank. Percentiles are priorities, not attack probabilities.
4. Interaction groups: unordered actual endpoint pair, host-qualified by existing
   loader, across relations, bounded total span 10 seconds (not a sliding chain).
   Max-share score within each group. No free event retention and no new POIs.
5. Retrieval: build v5 pool, add reachable positive-score events in its groups;
   keep base anchors, cap total anchors at max(32768,8B), extras ranked by score
   then event-ID tie. Witnesses retain raw costs. All algorithms count raw edges.
6. Main = calibrated frequency diffusion + max-shared channel score + expanded
   pool + v5 greedy utility lambda1. Controls: pool only, history only, channel
   only, same full score with lambda0, same full score with v4 full-candidate
   50/50 witness portfolio; matched no-frequency, degree-PPR, degree-heat.
   MILP uses primary pool/linear score at all-POI 1024 only, both tracks, original
   20s limit and .01 gap. Bounds apply to restricted linear objective only.
7. Same caps 64/256/1024/4096, primary1024; both tracks; POI-deletion only1024.
   Same frozen partial-positive reference, post-selection evaluator. Prior v5
   decisions reused only after input/source verification. Official metrics NA.
8. Cache DB aggregates and calibrated arrays with hashes and split metadata.
   Source configuration/code frozen before evaluation. Atomic publication of
   outputs; a parent process must finish before its child consumes output.
9. Report both event recall and critical group/stage coverage, failures, cold
   starts, cost, and pool-positive coverage AFTER selection. Fresh-process profile
   for main, channel-only and matched heat at1024; cold history build separate.

## Sources and claims
ECDF inspiration, not a full ECOD implementation:
https://arxiv.org/abs/2201.00382
PPR/heat remain prior formula adapters, not GDC/hk-relax whole-paper reproductions:
https://proceedings.neurips.cc/paper/2019/hash/23c894276a2c5a16470e6a31f4618d73-Abstract.html
No approximation, causal correctness, or attack-probability guarantee is claimed.
