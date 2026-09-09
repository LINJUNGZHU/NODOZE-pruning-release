# PS-RDP Submission-Grade Evaluation Protocol

This document separates what the implementation can establish now from what a competitive security/data-mining paper must still establish. “Submission-grade” here means auditable methodology; it is not a claim of acceptance at any venue.

## Claim boundary

PS-RDP is a post-alert, POI-conditioned provenance-graph pruning operator. It does not claim to be an end-to-end attack detector. Its online inputs are the provenance graph, completed-history frequency statistics, declared POIs, and prior online pruning state. Reference attack events and paths are evaluator-only data.

The primary method claims are:

1. complete edge-level accountability: every candidate edge has a persisted score, components, provenance, and decision;
2. prefix consistency: adding a POI cannot reduce any existing aggregate edge score or rewrite an older POI-local score;
3. controlled operational change: fixed-budget edge removal has separate declared, exact atomic-packing, and effective bounds; a violation fails closed;
4. honest structural guarantees: disconnected candidates and infeasible budgets are explicit states;
5. high compression with measured preservation of independently derived or reviewed attack evidence.

Scores are heuristic importance values. They are not probabilities, calibrated attack likelihoods, precision estimates, or substitutes for exhaustive labels.

## Required competitors

All methods must receive the same candidate graph and exact raw-event budget:

- full candidate graph (no pruning);
- uniform random edges, at least five fixed seeds;
- temporal-nearest-to-POI;
- degree/frequency filtering;
- rarity only;
- diffusion only;
- legacy joint RDP-Guard;
- PS-RDP without bounded churn;
- full PS-RDP;
- faithful or clearly labelled adaptations of NoDoze and DEPIMPACT;
- directed personalized PageRank and max-product temporal diffusion variants;
- NODLINK/ORTHRUS/KAIROS/MAGIC/FLASH only when the experiment supports their detector-level assumptions.

The method comparison must never grant one baseline a different candidate set, hidden protection rule, or byte/event budget.

## Factorial ablations

Report `rarity`, `diffusion`, `DEPIMPACT`, and `behavior` independently and in combinations. Because rarity and impact can influence both transmission and terminal fusion, include “transmission only” and “fusion only” variants. Separately ablate noisy-OR, frozen local scores, bounded churn, atomic grouping, and the strict certificate.

Sensitivity axes are historical window length, high-score quantile, absolute threshold, churn slack, damping, POI order perturbation, candidate-window perturbation, missing data-size rate, and behavior-clustering fallback.

## Datasets and units

The immediate regression set is DARPA TC E3 CADETS UBC-06/12/13. A paper-scale evaluation should expand to available CADETS, THEIA, and CLEARSCOPE scenarios from E3/E5 and OpTC where licensing and labels permit. Scenario/host is the paired statistical unit; POI prefixes from one host are correlated observations and must not be treated as independent datasets.

Use independently reviewed event/path annotations where available. Automatically derived UBC-core-to-POI paths must remain labelled `derived_reference_path`, never `human_verified_attack_path`.

## Metrics

Always report numerator, denominator, and value for:

- candidate and final reviewed-node/event recall;
- conditional retention given candidate coverage;
- exact derived and independently reviewed path retention;
- candidate/final connected ordered-stage pairs;
- raw-event and node compression;
- unused raw-event budget and certificate overflow;
- consecutive-prefix Jaccard, added/removed edges, churn bound, and score monotonicity;
- high-score retention and analyst-facing evidence count;
- runtime per POI, selection time, ledger time, sampled peak RSS, convergence status, and resource stops;
- frequency/history coverage, data-size coverage, OOV coverage, and clustering backend.

Do not report precision, FPR, or F1 by treating every unlabelled provenance event as benign. Do not call retained score mass “confidence.”

## Statistical analysis

Use at least five fixed seeds for stochastic baselines and clustering variants. Report paired bootstrap confidence intervals across scenarios/hosts. With enough paired units, use Wilcoxon signed-rank for two methods or Friedman followed by corrected pairwise comparisons for multiple methods. Report effect sizes and all tested hypotheses, not only significant comparisons. Hyperparameters require a disjoint development set or a nested protocol.

## Artifact requirements

Publish configs, POI manifests and their hashes, the canonical `candidate-graph.jsonl.gz`, complete score ledgers, high-score indexes, decision reasons, certificate states/witness identities, environment/dependency versions, fixed random seeds, process logs, and one-command deep verification. The verifier must recompute graph identity, score rank/order, high-score cutoff including ties, and budget decisions. A result missing a verified ledger, violating churn, or marked `incomplete` is excluded rather than silently averaged.

## Primary research anchors

- NoDoze, NDSS 2019: <https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_03B-1-3_UlHassan_paper.pdf>
- DEPIMPACT, USENIX Security 2022: <https://www.usenix.org/system/files/sec22-fang.pdf>
- NODLINK, NDSS 2024: <https://www.ndss-symposium.org/ndss-paper/nodlink-an-online-system-for-fine-grained-apt-attack-detection-and-investigation/>
- MAGIC, USENIX Security 2024: <https://www.usenix.org/system/files/usenixsecurity24-jia-zian.pdf>
- ORTHRUS, USENIX Security 2025: <https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf>
- PIDSMaker benchmark study, USENIX Security 2025: <https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf>
- Statistical comparison guidance: <https://www.jmlr.org/beta/papers/v7/demsar06a.html>
