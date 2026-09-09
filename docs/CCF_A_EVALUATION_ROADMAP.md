# PS-RDP-CPF: CCF-A-Target Evaluation Roadmap

Date: 2026-09-08

## Positioning

PS-RDP-CPF addresses provenance-graph dependency explosion with four coupled
ideas: pre-POI historical rarity, POI-conditioned time-respecting diffusion,
prefix-stable noisy-OR aggregation, and a budgeted causal-path-forest guard.
The current implementation is a submission-grade *target*, not evidence that a
CCF-A venue will accept the work.

The defensible claim for the current CADETS experiment is:

> Given report-derived POI proxies, PS-RDP-CPF compresses the fixed candidate
> graph under one global raw-event budget while preserving a predeclared,
> independently verifiable causal path cover. Ground truth is used only after
> online selection is frozen.

It is not yet defensible to claim detector-realistic end-to-end attack
detection, universal superiority, or calibrated anomaly probabilities.

## Implemented rigor gates

1. Every candidate edge receives one finite score row, complete component and
   rarity evidence, POI provenance, rank, percentile, and a decision for every
   budget.
2. High-anomaly output is the complete threshold set (absolute threshold versus
   positive-score quantile, including all ties), not a hand-picked Top-N list.
3. POI-local scores are immutable across prefixes; aggregate edge scores are
   monotone by noisy-OR.
4. All raw events, atomic expansions, POIs, and witness bridges are charged to
   the same budget.
5. Causal branches are declared before search. A disconnected declared chain
   fails closed and cannot be relabeled as a branch after seeing the graph.
6. The v3 validator independently rebuilds the input path cover, candidate and
   retained reachability, witness continuity, budgets, churn, ledger hashes,
   and per-edge decisions.
7. The background launcher reports success only after independent validation.

## Required paper-scale experiments

| Dimension | Minimum defensible evaluation |
|---|---|
| Data | Multiple DARPA TC corpora and attack scenarios; benign-only windows; at least one non-DARPA provenance source if licensing permits |
| Baselines | Full graph, random, temporal, frequency-only, rarity-only, diffusion-only, legacy RDP-Guard, adapted NoDoze, adapted DEPIMPACT, and a recent learned provenance baseline |
| Ablations | Remove rarity, diffusion, behavior, impact, path cover, noisy-OR stability, and churn control one at a time; include interaction ablations |
| Budgets | Full compression–retention curves rather than only 20%; report actual raw-event ratio, not requested ratio |
| Seeds | Report-derived oracle POIs and detector-produced POIs in separate tables; inject controlled false-positive and delayed POIs |
| Statistics | Repeated stochastic baselines/seeds, paired per-scenario deltas, bootstrap confidence intervals, and corrected non-parametric tests |
| Efficiency | Wall time, phase time, peak RSS, on-disk bytes, ledger overhead, and scaling versus candidate edge count |
| Labels | Human-reviewed strict attack paths where possible; clearly separate derived-reference paths from verified paths |

## Primary metrics

- raw-event and node compression;
- verified/derived complete-path retention;
- attack-event recall and conditional pruning recall;
- unseeded-terminal path retention to expose POI hard-protection bias;
- minimum legal POIs for full path restoration;
- path-cover certificate validity and witness length/cost;
- prefix score monotonicity, retained-set Jaccard, and bounded churn;
- high-anomaly precision/recall when independent edge labels exist;
- runtime, memory, storage, and evidence-generation overhead.

All results must show numerators and denominators. A missing denominator is
reported as null, never converted to zero or one. Oracle-POI results and
detector-POI results must never be pooled.

## Remaining architectural hardening

The current code enforces online-before-offline ordering inside one process and
the validator rejects attack labels in the online input. A stronger camera-ready
artifact should split execution into two processes:

1. an online process receives only the database, configuration, and POIs, then
   seals the candidate graph, scores, decisions, and hashes;
2. an offline evaluator receives that immutable artifact plus ground truth.

This process boundary would turn the current tested control-flow isolation into
a system-level non-interference argument. It is a follow-up requirement, not a
claim made by the present run.

## Acceptance bar for any headline table

A row is publishable only if the producer completed, every edge ledger passed
deep verification, the causal path-cover certificate is valid, the raw-event
budget is feasible, the churn bound is satisfied, and the independent sweep
validator exits zero. Failed rows remain archived as failure evidence but are
excluded from headline comparisons.
