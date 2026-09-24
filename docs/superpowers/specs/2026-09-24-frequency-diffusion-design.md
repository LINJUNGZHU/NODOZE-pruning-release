# Frequency-conditioned relation-balanced diffusion experiment

## Scope and hypothesis
Keep the existing frozen frequency rarity and seeded diffusion backbone. Test whether semantic-object ubiquity correction, relation-balanced random walks, and bounded parallel-event episodes improve the five development cases. This is a research candidate, not a claim of publication novelty or SPARSE superiority.

The current RASP scorer uses undirected interaction channels; temporal causal-fork witnesses are enforced by selection. The existing RCVP branch already has temporal propagation and relation mixing, so relation balance alone is not a new contribution. The experimental contribution is the combination with duplicate-invariant semantic frequency and evidence-preserving episode admission, evaluated by separate ablations.

## Method
1. Host-qualified node IDs. Reverse EXECUTE only when the ledger says process -> file; preserve process-version -> process EXECUTE.
2. Historical rarity stays frozen. Candidate-local semantic ubiquity counts distinct process instances per (host, object semantic key, relation), not repeated events. Its inverse-log weight combines geometrically with historical rarity. This is explicitly transductive, not a clean historical estimate.
3. Each incident relation receives equal random-walk mass at a node; within relation, conductance follows frequency. Personalized and process-background PageRank produce positive log lift. Mix endpoint geometric and arithmetic evidence equally to test one-sided entry evidence. Compare geometric-only ablation.
4. Episodes group exact host-qualified directed endpoints and relation within a maximum 10-second span from first event, never unbounded adjacent-gap chaining. Every group retains a reversible raw membership map.
5. Rank episodes by maximum member score. Admit an episode with an existing strict temporal fork witness for its highest ranked reachable member. Charge ALL raw members and raw connector events against a hard raw-event cap. Other parallel members are corroborating evidence, not individually certified causal paths.
6. Always retain declared POIs. No labels, attack filenames, IP lists, old decisions, or extra POIs enter scoring or selection. Use fixed raw caps 64, 256, 1024, 4096 on all five cases.

## Comparison
Frozen config before evaluation. Methods: old RASP with same episode selector; full; no semantic frequency; geometric endpoints only; no episode expansion; no frequency (both frequency channels removed). Also report old-score top-K at same raw cap and prior optimized results, clearly separating historical runs.
Metrics: raw events, 10s episodes, retained partial-positive events/groups/stages, closed-world proxy FP/FN/P/R/F1. Official-equivalent metrics remain NA. Report runtime and RSS. Five cases are development data; no held-out claim. Case5 remains inferred TRACE mapping. External-alert-free POIs remain report-derived oracle seeds, not autonomous POI discovery.

## Literature anchors
- SPARSE, arXiv 2024: https://arxiv.org/html/2405.02629v1 — streaming suspicious graph and contextual paths; parallel edge merging.
- NODLINK, NDSS 2024: https://www.ndss-symposium.org/wp-content/uploads/2024-204-paper.pdf — online Steiner-tree reconstruction, IDF anomaly evidence; its approximation results do not transfer to our heuristic.
- ORTHRUS, USENIX Security 2025: https://www.usenix.org/conference/usenixsecurity25/presentation/jiang-baoxiang — attribution quality, temporal graph learning.
- KAIROS, IEEE S&P 2024: https://spg.cs.ubc.ca/publication/2024-sp/ — temporal graph anomaly detection and reconstruction.
- MAGIC, USENIX Security 2024: https://www.usenix.org/conference/usenixsecurity24/presentation/jia-zian — masked graph representation learning.
- FLASH, IEEE S&P 2024: https://ieeexplore.ieee.org/document/10646725/ — semantic/temporal embeddings and graph context.
- Sometimes Simpler is Better, USENIX Security 2025: https://www.usenix.org/conference/usenixsecurity25/presentation/bilot — consistent evaluation and simpler baselines.
- The Case for Learned Provenance-based System Behavior Baseline, ICML 2025: https://proceedings.mlr.press/v267/zhu25k.html — adaptive behavioral baselines.
- Diffusion Improves Graph Learning, NeurIPS 2019: https://proceedings.neurips.cc/paper/2019/hash/23c894276a2c5a16470e6a31f4618d73-Abstract.html — graph diffusion and sparsification, already related work for RASP.

A GNN is deferred: five previously inspected attacks do not provide a defensible independent training/test split. Adding one now would confound architecture and leakage.

## v2 revision after v1 evaluation and review
The v1 semantic count incorrectly split process incidence by endpoint orientation; v2 pools incidences before counting. The v1 archive remains marked superseded. Episode priority now uses all members, with a reachable witness, as specified.

Preserve existing bounded POI semantic continuation rules uniformly on all five cases (all optional rules on, no raw command-line scan). Mandatory continuation edges consume the same raw budget but never become diffusion seeds. When mandatory evidence exceeds a budget, omit that hybrid budget and record the mandatory count; do not enlarge the cap or truncate mandatory evidence. Add classic+continuations and full+continuations controls. These are inherited development-tuned rules, not a new contribution or independently learned discovery. Primary remains 1024 raw events; v2 primary method full_hybrid. v1 showed no all-case gain: THEIA3 full ties old-score top-K at 1024, and no-frequency can outperform full. Preserve those negative controls.

## v3 revision
Partition legacy continuation rules by exact host (a mixed-host synthetic test exposed that some legacy helpers ignored host). Rerun every case; previous v2 artifacts remain archived.

Exploratory occupancy priority: multiply the existing event score by sqrt(number of distinct timestamps in its 10-second episode). This incorporates sublinear short-window frequency evidence while identical-record replication at the same timestamp contributes nothing. It changes selection priority, not diffusion probabilities or historical frequency. Compare burst and classic_burst, each with and without identical semantic continuations. Primary full_hybrid and all raw caps stay unchanged. No assertion of statistically calibrated burst detection. Hypothesis motivated by v2 THEIA1 miss analysis: true local ingress edges are temporally reachable but ranked 69,503 to 280,310. No exemplar IDs or attack semantics are fed back into the method.
