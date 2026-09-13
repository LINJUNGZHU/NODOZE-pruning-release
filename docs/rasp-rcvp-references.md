# RASP-RCVP research sources

Checked on 2026-09-13. These sources motivate individual design choices; they
do not establish that this implementation reproduces a paper or that its
development results generalize.

## Primary sources

- Wajih Ul Hassan et al., “NoDoze: Combatting Threat Alert Fatigue with
  Automated Provenance Triage,” NDSS 2019,
  [official author publication page](https://sts.cs.illinois.edu/papers/paper/NoDozeCombattingThre20190224.html),
  [paper DOI](https://doi.org/10.14722/ndss.2019.23349). NoDoze motivates
  historical-frequency evidence, propagation on an alert dependency graph,
  and concise investigation output. RASP-RCVP keeps rarity as heuristic
  evidence and does not interpret a propagated score as attack probability.

- Zhiqiang Fang et al., “Back-Propagating System Dependency Impact for Attack
  Investigation,” USENIX Security 2022,
  [official USENIX paper](https://www.usenix.org/system/files/sec22-fang.pdf).
  DEPIMPACT motivates the backward entry-point search followed by forward
  causality verification. RASP-RCVP implements its own strict timestamp-block
  operator and frozen witness audit; it is not a reproduction of DEPIMPACT.

- Baoxiang Jiang et al., “ORTHRUS: Achieving High Quality of Attribution in
  Provenance-based Intrusion Detection Systems,” USENIX Security 2025,
  [official conference page](https://www.usenix.org/conference/usenixsecurity25/presentation/jiang-baoxiang),
  [official implementation](https://github.com/ubc-provenance/orthrus).
  ORTHRUS motivates reporting analyst-facing attribution size and explicitly
  separating detection from attack reconstruction. The present admitted UBC
  labels support positive-entity retention only; they do not supply exhaustive
  negatives or independently reviewed event paths, so precision, F1, and
  verified-path retention remain N/A.

- Wei Qiao et al., “Slot: Provenance-Driven APT Detection through Graph
  Reinforcement Learning,” ACM CCS 2025,
  [ACM DOI](https://doi.org/10.1145/3719027.3744788),
  [author-hosted paper](https://yebof.github.io/assets/pdf/qiao2025ccs.pdf).
  Slot motivates treating provenance relations separately. RASP-RCVP uses a
  deterministic relation-family operator; it does not reproduce Slot's GNN or
  reinforcement-learning policy.

- Dongpeng Hou et al., “A Generalized Diffusion Framework with Learnable
  Propagation Dynamics for Source Localization,” IJCAI 2025,
  [official proceedings page](https://www.ijcai.org/proceedings/2025/325).
  Its paired forward/reverse formulation motivates evaluating reverse source
  support with a forward reconstruction channel. The implementation here is a
  label-free temporal sweep rather than its learned generative diffusion.

- Le Cheng et al., “SourceDetMamba: A Graph-aware State Space Model for Source
  Detection in Sequential Hypergraphs,” IJCAI 2025,
  [official proceedings page](https://www.ijcai.org/proceedings/2025/306).
  The reverse temporal/topological perspective is relevant to source tracing;
  RASP-RCVP does not introduce Mamba or a learned state-space model.

- Di Jin et al., “Rethinking Contrastive Learning in Graph Anomaly Detection:
  A Clean-View Perspective,” IJCAI 2025,
  [official proceedings page](https://www.ijcai.org/proceedings/2025/335).
  Its progressive purification idea motivates testing incremental removal.
  RASP-RCVP's removal policy is independently defined and guarded by raw-event
  budgets and provenance certificates.

- Fei Shao, Jia Zou, Zhichao Cao, and Xusheng Xiao, “ProGQL: A Provenance
  Graph Query System for Cyber Attack Investigation,” 2025 technical report,
  [author-deposited arXiv record](https://arxiv.org/abs/2510.22400). The title,
  authors, and report are verified; no peer-reviewed venue was found, so this
  document does not assign one. ProGQL motivates constrained incremental
  traversal and explicit propagation/audit operators. RASP-RCVP does not
  implement ProGQL, its query language, or its database execution engine.

- Mingjian Lu, Haolai Che, Yangxin Fan, Qu Liu, Fei Shao, Tingjian Ge,
  Xusheng Xiao, and Yinghui Wu, “Training-free Counterfactual Explanation for
  Temporal Graph Model Inference,” ICLR 2026,
  [official ICLR proceedings entry](https://proceedings.iclr.cc/paper_files/paper/2026/hash/36bc2989d4b3371654fce3cb9a1a6889-Abstract-Conference.html).
  TemGX motivates treating a temporal explanation as a constrained subgraph
  with an auditable time-decay objective. Counterfactual generation and TGNN
  model explanation are deferred; the current selector only removes groups
  under fixed provenance certificates.

- Langzhang Liang, Fanchen Bu, Zixing Song, Zenglin Xu, Shirui Pan, and Kijung
  Shin, “Mitigating Over-Squashing in Graph Neural Networks by
  Spectrum-Preserving Sparsification,” ICML 2025,
  [official PMLR proceedings entry](https://proceedings.mlr.press/v267/liang25a.html).
  It motivates reporting whether sparsification preserves global structural
  diagnostics. Its spectral rewiring method is deferred because adding or
  rewiring weakly undirected edges would violate this experiment's frozen raw
  event identities and directed temporal witnesses.

- Sareh Mohammadi, Hugo Kermabon-Bobinnec, Azadeh Tabiban, Lingyu Wang, Tomás
  Navarro Múnera, and Yosr Jarraya, “CONnecting The EXtra doTS (CONTEXTS):
  Correlating External Information about Point of Interest for Attack
  Investigation,” IEEE Symposium on Security and Privacy 2025,
  [official conference listing](https://sp2025.ieee-security.org/accepted-papers.html),
  [IEEE record](https://ieeexplore.ieee.org/document/11023372/). CONTEXTS
  motivates separating externally supplied POI context from graph-derived
  scoring. External exploit/vulnerability enrichment is deferred; only the
  explicitly supplied POI is an online seed, and reference attack labels are
  opened after masks freeze.

- “TeRed: Normal Behavior-Based Efficient Provenance Graph Reduction for
  Large-Scale Attack Forensics,” IEEE Transactions on Information Forensics
  and Security, volume 20, 2025,
  [official IEEE record](https://ieeexplore.ieee.org/document/11133429/), DOI
  10.1109/TIFS.2025.3601381. TeRed motivates comparing reductions against
  normal-behavior redundancy while checking that investigation evidence is
  retained. Its learned normal-behavior patterns and unit-test training corpus
  are deferred; RASP-RCVP's redundancy term is label-free and deliberately
  weak. The accessible IEEE metadata verified the title, journal, year, and
  DOI; author names were not exposed by the primary page and are therefore not
  asserted here.

- Bo Zhang, Yansong Gao, Changlong Yu, Boyu Kuang, Zhi Zhang, Hyoungshick Kim,
  and Anmin Fu, “TAPAS: An Efficient Online APT Detection with Task-guided
  Process Provenance Graph Segmentation and Analysis,” USENIX Security 2025,
  [official USENIX publication page](https://www.usenix.org/conference/usenixsecurity25/presentation/zhang-bo-tapas).
  TAPAS motivates raw-event storage/runtime reporting and process-centered
  summaries. Its learned LSTM-GRU representations, task segmentation, and
  online detector are deferred; the current method keeps original events and
  does not claim TAPAS's detection accuracy or compression factors.

- Shaofei Li, Feng Dong, Xusheng Xiao, Haoyu Wang, Fei Shao, Jiedong Chen, Yao
  Guo, Xiangqun Chen, and Ding Li, “NODLINK: An Online System for Fine-Grained
  APT Attack Detection and Investigation,” NDSS 2024,
  [official NDSS publication page](https://dev.ndss-symposium.org/ndss-paper/nodlink-an-online-system-for-fine-grained-apt-attack-detection-and-investigation/),
  [paper DOI](https://doi.org/10.14722/ndss.2024.23204). NODLINK motivates
  concise online investigation graphs, explicit resource accounting, and
  preserving connectivity among important events. Its online Steiner-tree
  approximation, screening system, and claimed approximation guarantees are
  deferred; RASP-RCVP uses fixed temporal witnesses and makes no NODLINK
  approximation claim.

## How the experiment uses these ideas

The A–G matrix isolates relation mixing, time/fanout attenuation, backward
localization, forward verification, and progressive certificate-preserving
selection. All variants share the same frozen candidate ledger and raw-event
budgets. The runner opens reference labels only after every mask and the audit
digest are persisted. Candidate coverage, retention conditional on candidate
coverage, and end-to-end pruned recall are reported as separate numerator,
denominator, and value triplets.

The RCVP propagation kernel is an exact, one-pass temporal max-product sweep
over strict timestamp blocks. It is mathematically different from stationary
PageRank/PPR: it publishes a block only after every event at that timestamp has
read the prior state, reports `exact_temporal_max_product`, one pass, and zero
iterative residual, and never describes those diagnostics as PPR convergence.
Relation-family transitions use deduplicated directed interactions and
normalize over the temporally active eligible state at each step; forward and
backward witnesses retain the original event indices.

Spectral or weakly undirected sparsification measures are optional offline
diagnostics. They are not used to restore an edge, override directed temporal
legality, select a budget, or tune a relation weight.
