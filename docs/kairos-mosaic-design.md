# KAIROS-MOSAIC Design

Date: 2026-09-15

Status: approved architectural experiment; CADETS E3 development only; does not replace A_rasp defaults

## 1. Goal and non-goals

KAIROS-MOSAIC (Multi-Objective Source-aware Adaptive Investigation Compression) uses native KAIROS event loss, anomalous queues, and summary scaffolds as a continuous evidence field. It reconstructs a high-recall temporal investigation envelope and then finds the smallest proof-carrying graph that meets multiple investigation-quality targets.

The primary question is not “what survives a fixed 20% budget?” It is: “under an FN or known-FN target, what is the minimum projected investigation graph and associated raw-event cost?” The 20% point remains a legacy comparison only.

The first version is deterministic and explainable. It does not train a new neural model, copy diffusion/Mamba/cross-attention architectures, treat KAIROS as Ground Truth, or assume a KAIROS anomaly is a POI/source/sink. Phase 2 RR, forward sphere, motif selection, and hard preserver remain frozen as negative-result ablations.

## 2. Frozen baseline

Phase 2 is frozen by hashes:

- online: `fd6a151e5b1126cfd9bf0439cdc0e1ada32615a420690e3268d05e1a051ac7ca`
- offline evaluation: `ae58bc761b7dacce0c514142fc25eba9c81fa70427ff6ecff2ae1066a6b59f33`

CADETS E3 observable attack-node results are V0 `41/68 → 37/68`, V4 `44/68 → 37/68`, and C_branch_fair `44/68 → 41/68`. Stochastic RR and unrestricted forward expansion do not exceed the 44-node candidate ceiling. Motifs do not stably beat edge-only branch fairness. Hard reachability protection adds paths but violates a tiny query budget. The branch-fair selector, not RR/forward, is the Phase 2 runtime bottleneck.

## 3. Considered approaches

### 3.1 Chosen: native evidence field and proof-carrying reduction

Preserve KAIROS event, queue, and summary layers; map them deterministically to raw provenance events; build source/target/long-gap proposals; complete only compatible causal corridors; optimize robust objectives; safely delete from a high-recall envelope. This preserves provenance semantics and supports honest event and projected-edge accounting.

### 3.2 Rejected: flatten KAIROS into ORTHRUS alerts

This is easy to integrate but destroys loss percentiles, queue membership, summary components, and detector-native temporal context. It also repeats the failed assumption that one alert endpoint is the investigation source.

### 3.3 Deferred: learned inverse diffusion and target matcher

A learned model may eventually improve matching, but CADETS 06/12/13 cannot support leakage-free training and held-out claims. The first version uses explicit label-free features and frozen KAIROS model outputs.

## 4. Cross-domain ideas and exact transfer boundary

### GDFSL, IJCAI 2025

- Original problem: infer diffusion sources from observed infected-state snapshots under varying propagation dynamics.
- Borrowed idea: source localization is an inverse problem; observations need not be sources or sinks.
- Provenance fit: KAIROS anomalous events are observations from which upstream causal origins can be explained and forward-verified.
- Not copied: neural diffusion, learned noise, infection-state assumptions.
- Failure addressed: Phase 2 expanded roots selected from local/stochastic support without demanding that they explain multiple native evidence observations.
- Source: https://www.ijcai.org/proceedings/2025/325

### SourceDetMamba, IJCAI 2025

- Original problem: source detection in sequential hypergraphs with graph-aware state-space modeling.
- Borrowed idea: reverse temporal reasoning and higher-order interaction context.
- Provenance fit: process-file-process, process-fork-execute, and network-process-execute structures provide path proof.
- Not copied: Mamba/state-space model or learned hypergraph embeddings.
- Failure addressed: pairwise-only candidate ranking misses semantically complete bridges.
- Source: https://doi.org/10.24963/ijcai.2025/306

### CRAFT, NeurIPS 2025

- Original problem: future temporal-link prediction, especially unseen interactions, using target-aware source-history matching.
- Borrowed idea: score compatibility with the current target/incident, rather than only global anomaly or PPR.
- Provenance fit: a globally common edge can be uniquely compatible with one incident’s lineage, resource, endpoint, or temporal pattern.
- Not copied: cross-attention or learnable identifier embeddings.
- Failure addressed: attack edges with very low global A_rasp rank never enter or survive the candidate graph.
- Source: https://proceedings.neurips.cc/paper_files/paper/2025/hash/036912a83bdbb1fd792baf6532f102d8-Abstract-Conference.html

### TAMI, NeurIPS 2025

- Original problem: temporal link prediction under long-tailed interaction frequency and interval distributions.
- Borrowed idea: logarithmic time-distance encoding and explicit per-pair history.
- Provenance fit: APT relationships can reappear after long inactive periods and should not vanish under exponential decay.
- Not copied: neural time encoders or link-history aggregation network.
- Failure addressed: one-hour/simple exponential history suppresses rare, long-gap causal compatibility.
- Source: https://proceedings.neurips.cc/paper_files/paper/2025/file/aa963ac256590bb7ad5fc26c68229a3a-Paper-Conference.pdf

### SALoM, NeurIPS 2025

- Original problem: combine long- and short-range dependencies in temporal graph networks.
- Borrowed idea: maintain short exact interactions and a separate long-term compact sketch, then fuse explicitly.
- Provenance fit: exact recent causality and historical semantic recurrence carry different evidence.
- Not copied: neural memories, LSMU, or information bottleneck training.
- Failure addressed: a single fixed window discards either fine recent order or long-lived APT context.
- Source: https://papers.neurips.cc/paper_files/paper/2025/hash/20f94998511f25bb6378cae0e098bc46-Abstract-Conference.html

### Improved Online Reachability Preservers, SODA 2025

- Original problem: sparse directed subgraphs that preserve reachability for online demand pairs.
- Borrowed idea: explicitly represent reachability demands and their witness paths.
- Provenance fit: analyst-relevant source/anchor and corridor reachability can be replayed from raw events.
- Not copied: worst-case online preserver construction and unconditional hard guarantees.
- Failure addressed: Phase 2 hard protection overflows tiny budgets, so MOSAIC assigns each demand a prize and accepts controlled low-prize loss.
- Source: https://epubs.siam.org/doi/10.1137/1.9781611978322.149

### Fair Influence Maximization, TKDE 2025

- Original problem: maximize influence while avoiding community starvation.
- Borrowed idea: logarithmic/concave utility over branch coverage.
- Provenance fit: large daemon branches must not starve a small, strongly supported attack branch.
- Not copied: influence cascade estimation or demographic fairness semantics.
- Failure addressed: Phase 1 recovered low-score branches that legacy ranking discarded.
- Source: https://www.microsoft.com/en-us/research/publication/a-scalable-algorithm-for-fair-influence-maximization-with-unbiased-estimator/

### Multiobjective Submodular Maximization, ICML 2025

- Original problem: maximize the minimum of multiple submodular functions at scale.
- Borrowed idea: robust worst-objective satisfaction instead of a single weighted sum.
- Provenance fit: KAIROS, branch, anchor, path-prize, and relevance quality must not collapse independently.
- Not copied: the paper’s complete approximation algorithm or multilinear optimization.
- Failure addressed: Phase 2 improves node recall while regressing strict paths at 5%/10%.
- Source: https://proceedings.mlr.press/v267/spaeh25a.html

### TemGX, ICLR 2026

- Original problem: training-free counterfactual temporal-subgraph explanations under constrained optimization.
- Borrowed idea: separate structural influence and temporal contribution, then select and verify temporal subgraphs.
- Provenance fit: corridors/envelopes are explanations with strict replay witnesses rather than raw rankings.
- Not copied: TGNN counterfactual inference or its approximation guarantees.
- Failure addressed: unconstrained expansion returns structurally nearby noise without an explanation proof.
- Source: https://proceedings.iclr.cc/paper_files/paper/2026/hash/36bc2989d4b3371654fce3cb9a1a6889-Abstract-Conference.html

### CVGAD, IJCAI 2025

- Original problem: graph anomaly detection with progressively purified clean views.
- Borrowed idea: reduce interference over a few stable rounds in a derived propagation view.
- Provenance fit: high-frequency/high-fanout, zero-unique-coverage edges can be downweighted without deleting raw audit facts.
- Not copied: contrastive anomaly model or destructive graph cleaning.
- Failure addressed: one-shot clean weighting and hub fan-out contaminate root/candidate priority.
- Source: https://ijcai-preprints.s3.us-west-1.amazonaws.com/2025/80.pdf

### APEX², KDD 2025

- Original problem: adapt tiny personalized KG summaries as query interests change.
- Borrowed idea: persistent investigation state and incremental checkpoints when new queues arrive.
- Provenance fit: later KAIROS queues should update affected roots/corridors rather than rebuild an incident from scratch.
- Not copied: personalized KG objective or full streaming update algorithm.
- Failure addressed: Phase 2 repeatedly materializes and globally reselects large per-query graphs.
- Source: https://arxiv.org/abs/2412.17336

## 5. Native KAIROS adapter and isolation

`KairosEvidence` retains raw loss, query-local percentile, native anomaly flag, queue IDs and strength, summary membership/component, source, destination, relation, and timestamp. `KairosMappingAudit` reports native, exact, tolerant, ambiguous, and unmapped counts plus hashes.

Mapping order is: explicit raw event identity; exact `(src,dst,normalized_relation,timestamp)`; deterministic bounded tolerance. A candidate is accepted only if exactly one raw event matches at the current tier. Ambiguous mappings are rejected, never resolved by row order.

The online adapter may parse reconstruction and anomalous-queue artifacts but may not import KAIROS `evaluation.py`, `attack_investigation.py`, attack lists/windows, ORTHRUS/PDF/DepImpact GT, or local offline evaluators. Online canonical artifacts reject GT fields. An AST/import test enforces this boundary.

## 6. Anchor components and proposal channels

Native evidence is grouped into `KairosAnchorComponent` by queue membership first, then deterministic shared-entity, strict causal, summary-component, or target-compatibility links. A component records event IDs, nodes, queues, summary edges, loss mass, time range, host, and relation profile. Fixed elapsed-time sessions alone never create a component.

The investigation envelope is the union of:

1. KAIROS-native high-loss, queue, and summary proposals.
2. Deterministic source-aware inverse coverage. A root is ranked by weighted explained evidence/component mass, relation/path/anchor diversity, with coverage saturation and resource bounds—not fixed depth or stochastic RR.
3. Target-conditioned bridge proposals supported by lineage, shared-resource semantics, remote endpoints, command/executable similarity, historical pair patterns, temporal compatibility, and neighborhood overlap.

Only roots with minimum component support, KAIROS support, or target compatibility expand forward. Each branch step needs KAIROS, target, rare-pair, another component, or corridor support.

## 7. Long-short temporal memory

`RarePairHistoryKey=(src semantic class, relation, dst semantic class)`. The short cache retains exact recent events. The long sketch retains log-time buckets, counts, representative timestamps, and a deterministic rare-pair reservoir.

For `delta >= 0`, `delta_log=log1p(delta/base_unit)`. Exponential and log-time scores are both emitted for ablation. Short and long scores remain separate before a configured, label-free fusion. Gap buckets are `<1s`, `1–10s`, `10–60s`, `1–10m`, `10–60m`, and `>1h`.

## 8. Corridors, envelope, motifs, and demands

`CausalCorridor` is a strict temporal k-shortest path between compatible components. Pairs must pass time order, host/domain, relation semantics, target match, and frontier overlap before search. Every corridor contains original event IDs, projected edges, path cost, KAIROS support, target match, and long-gap support.

Motifs are path `ProofFeature`s only. They improve proof strength but never become mandatory standalone units or consume an independent motif budget.

Each source-component, component-component, or entry/exit demand has a prize derived from native evidence, anchor/root support, path uniqueness, and branch uniqueness. A `PathBundle` carries raw replay witnesses. No abstract connectivity without raw events is admissible.

## 9. Robust selection and certified reduction

Objectives are independently normalized:

- `f_K`: KAIROS evidence coverage;
- `f_B`: concave branch coverage `sum_b w_b log(1+C_b)`;
- `f_A`: anchor-component coverage;
- `f_P`: path-demand prize coverage;
- `f_R`: investigation relevance.

The robust score is `min_i f_i(S)/tau_i`. Selection creates an incremental quality-versus-size trajectory over representative structural candidates, not all raw edges. Representative prefiltering retains per branch/component/relation/corridor top-K by relevance, KAIROS, path contribution, target compatibility, and every bridge candidate.

The primary output is the minimum prefix satisfying all targets. `CertifiedProgressiveReducer` then tries low-removal-risk units and deletes one only when all objective targets and strict temporal witnesses remain valid. Removal risk orders attempts; it never proves deletability.

## 10. Progressive propagation purification

`G_full` remains immutable. Up to four `G_prop^k` rounds downweight high-frequency, high-fanout, low-KAIROS, low-target-match, zero-unique-coverage interference. Stop on configured top-candidate/root instability or when changes saturate. No raw event is removed at this stage.

## 11. Evaluation-edge projection and GT contracts

Both costs are always reported:

- `raw_event_count`: retained raw audit records.
- `projected_edge_count`: canonical investigation dependencies.

`RAW_EVENT` maps one event to one edge. `DEPIMPACT_COMPATIBLE` merges events with equal source, destination, normalized relation, and configurable temporal merge group. Each projected edge retains all raw event IDs.

Ground Truth declares `COMPLETE_EDGE_GT` or `PARTIAL_POSITIVE_GT`. Complete GT reports TP/FP/FN/precision/recall/F1/FPR/FNR/#Edges and asserts `TP+FN=|GT|`, `TP+FP=#Edges`. Partial GT reports only known TP, known FN, unlabeled output edges, known recall, and #Edges. The current PDF manifest is `PARTIAL_POSITIVE_GT`; its unlabeled edges must not be called false positives.

Candidate ceiling is evaluated before selection. Final known FN is decomposed into candidate FN plus selection FN.

## 12. Experimental tracks

Track A fixes the existing incident/POI condition and uses KAIROS only as a prior. It is metric-aligned with DepImpact/NoDoze; it is apples-to-apples only if dataset, attack, complete GT, projection, and POI are also identical.

Track B uses native KAIROS components without manual POIs and separately reports detector window metrics and investigation metrics. It must never be presented as a direct POI-conditioned comparison.

KAIROS input ablation is K0 loss, K1 queues, K2 summary, K3 combined, K4 inverse, K5 target, K6 long-short. Retrieval R0–R4 and selection S0–S5 follow the requested order. Parameters use label-free stability or leave-one-scenario-out development probes; no generalization claim is allowed.

## 13. Existing KAIROS artifact facts and reproduction boundary

The frozen official-style CADETS E3 artifact contains a 325 MB model, reconstructed loss windows for days 3–7, queue summaries for days 5–7, and vectorized graphs through day 13. Official day-6/day-7 evaluation reports `TN=174, FP=1, FN=0, TP=4`, precision `0.8`, recall `1.0`, F1 `0.8889`, and one anomalous queue with five windows. This result is an offline reproduction check because the official evaluator embeds attack windows.

Native reconstructed event/queue artifacts currently exist only for day 6/7 test output. Scenario 12/13 require inference with the frozen model before Track A/B can claim three-scenario KAIROS coverage. Failure to produce those artifacts blocks the full experiment; it does not authorize substituting ORTHRUS alerts.

## 14. Performance architecture

No global heap over every raw event is allowed. Candidate generation uses indexed adjacency and bounded compatible pairs. Selection works over representative structural units with sparse counters and incremental checkpoints. Development targets are ordinary query under 2 seconds, large query under 10 seconds, selector/reducer p95 under 5 seconds, and RSS no more than 1.25× Phase 1. Any miss is reported as a failed practical-upgrade gate.

## 15. Deliverables and gate

Deliverables are deterministic online mapping/envelope/selection artifacts, separate offline evaluation, FN/known-FN versus projected-edge frontier, raw-event companion metrics, all requested ablations/tests, and `docs/kairos-mosaic-results.md`.

Only modules with measured independent benefit remain in the final method. The complete MOSAIC stack is never presumed best and does not become the default automatically.
