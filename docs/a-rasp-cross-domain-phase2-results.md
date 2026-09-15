# A_rasp 跨域重构 Phase 2：CADETS E3 实验报告

本报告只使用 DARPA TC CADETS E3。在线阶段输入为 ORTHRUS 告警、身份映射和历史图，不读取 ORTHRUS/PDF Ground Truth；标签仅在在线结果冻结后由独立评估脚本加载。除非特别注明，主比较点为相同 V0 原始事件预算的 20%。

## 1. Baseline reproduction

冻结基线复现成功。V0（原 A_rasp）在 68 个查询时刻可观察 ORTHRUS 攻击节点中，candidate 为 41/68，最终保留 37/68；V4（Phase 1）为 44/68 → 37/68。V4 相比 V0 解决了 3 个 candidate miss，但没有解决 selection miss。

20% 时 V0/V4 均读取 90,396 个原始事件，实际 keep ratio 为 19.9996%。V0 保留 11 个 PDF 关键事件、0 条完整 PDF 路径和 304 条严格时间路径；V4 保留 10 个、2 条和 304 条。这里的 cost 是逐 query 原始事件数之和，不是跨 query 去重后的事件并集。

## 2. Root-cause diagnosis

瓶颈分为两层：candidate-stage 有 24 个可观察攻击节点不在 V4 candidate 中；selection-stage 则把 44 个 candidate 攻击节点压成 37 个。前者主要不是“再多走一两跳”即可解决，后者是全局分数排序偏向大分支、稀释小攻击分支。

离线诊断还发现，若不施加 scenario-day、cutoff 和 hop 上界，后台 daemon/control fan-out 会产生巨大搜索空间。因此在线重构增加了独立于 GT 的候选增量保护：每个 query 最多加入 `max(50, min(2000, floor(0.02*|V4|)))` 个新事件，并忽略验证分数不超过 0.05 的 forward sphere。

## 3. Miss taxonomy

V4 的 24 个 candidate miss 来自 Scenario 12 的 11 个和 Scenario 13 的 13 个。标签可重叠：`CONTROL_DESCENDANT=14`、`FORWARD_DESCENDANT=1`、`NO_TEMPORAL_PATH=23`、`RELATION_UNSUPPORTED=22`。

这说明大多数 miss 在当前告警 cutoff、CADETS 因果方向和 12-hop 限制下没有合法时间路径。`RELATION_UNSUPPORTED` 仅表示该节点邻接到当前传播视图不采用的关系，不能单独视作因果结论。Scenario 12 的 11 个 miss 中，严格 forward reconstruction 可恢复 0 个；这也是 candidate recall 没有超过 44/68 的直接原因。

## 4. Modified files

核心新增/修改如下：

- `tc_pruning/offline_analysis/candidate_miss.py`：仅离线的 miss taxonomy。
- `tc_pruning/investigation/graph_views.py`、`propagation.py`：`G_full/G_prop/G_output` 与 clean propagation。
- `reverse_reachability.py`、`forward_sphere.py`：时间约束的反向覆盖与前向因果球。
- `motifs.py`、`reachability.py`：时间 motif 与 mandatory preserver。
- `evidence_units.py`、`branch_fair_selector.py`、`phase2.py`：原始事件成本、ECDF、分支公平选择与模式编排。
- `scripts/analyze_candidate_misses.py`：离线诊断入口。
- `scripts/run_a_rasp_cross_domain_phase2.py`：不接收 GT 参数的在线 A–H runner。
- `scripts/evaluate_a_rasp_cross_domain_phase2.py`：冻结后接入 ORTHRUS/PDF 的评估器。
- `configs/a_rasp_cross_domain_phase2.json`：全部实验参数。
- 8 个 Phase 2 单测文件及本报告。

## 5. New architecture

架构明确分离三张图：`G_full` 保留 cutoff 前原始事件；`G_prop` 只承载合法因果方向、时间与 clean 权重；`G_output` 是在统一 raw-event budget 下由 selector 输出的事件集合。执行链为：V4 candidate → clean propagation → Temporal RR → Forward Sphere → motifs → demand/preserver → branch-fair lazy greedy。V0、V4 和 A–H 消融共用同一组绝对预算。

新架构不是默认算法；它是实验模式。当前推荐只吸收被消融证明有效的 selector，不合并无 candidate 收益的搜索模块。

## 6. Reverse reachability algorithm

Temporal RR 从告警 anchor 逆向采样满足时间单调性的 witness，固定 seed `20260915`，每个 query 128 次、最多 12 hops、sketch 上限 64，并按 source support、关系多样性、路径多样性和 anchor support 排 root。9 个 query 共输出 72 个 top roots。

相比 fixed-depth backward，D_reverse 只让 aggregate candidate event union 从 164,481 增至 164,490，即新增 9 个事件；攻击 candidate 仍是 44/68，最终仍是 37/68。因此它找到了在线可验证的跨深度 root/witness，却没有找到新的 ORTHRUS 攻击节点，不能宣称有效突破。

## 7. Forward sphere algorithm

每个 RR root 只沿严格 forward causal edges 展开；告警 anchor 是终止点。每轮记录新增节点/事件、marginal verified gain 和停止原因，并用 backward/forward support 的调和平均形成 verification。72 个 sphere 都产生正验证信号。

E_forward 的 candidate event 数由 164,481 增至 164,629，但 candidate 攻击节点仍为 44/68，最终仍为 37/68。它比固定深度找到 148 个额外事件，但没有找到额外 GT 节点；Scenario 12 的 11 个 candidate miss 恢复数为 0。

## 8. Temporal motif design

motif 是带真实 witness event 的 evidence unit，成本等于 witness 中去重后的 raw-event 数。发现数量为：`COMMON_CAUSE_BRANCH=4`、`FILE_TRANSFER=79`、`NETWORK_CONSEQUENCE=13`；96 个都有正验证分数，总 raw-event cost 为 183。索引 join 避免了事件两两比较。

F_motifs 在 20% 保留 40 个攻击节点、307 条严格时间路径；C_branch_fair 为 41 和 308。到 30% F 才达到 41 个节点。现有证据不能证明 motif 比独立 edge 更易保留 file/control/network 攻击行为，因此它是负结果，不应进入推荐配置。

## 9. Reachability preserver

preserver 对 root-anchor temporal demand 计算最小原始事件 skeleton，并在选择前作为 mandatory events。72/72 个 demand 被保留，skeleton 总成本为 72 个原始事件。

aggregate 20% 下它只占 72/90,396 = 0.080% 的预算，但分配是逐 query 的：Scenario 06 的一个极小 query 预算仅 1，而 skeleton 成本为 8，溢出 7。因此 G/H 在所有预算档均不满足 per-query budget，不能与可行算法同榜。相对 C，它在 20% 把严格时间路径从 308 提到 310，完整 PDF 路径仍为 2；代价是预算不可行。结论是保留为 optional diagnostic mode，而不是默认 mandatory mode。

## 10. Branch-fair objective

selector 以 edge/motif evidence unit 为单位，使用 query-local ECDF 归一化相关度，通过 `log1p` 边际增益鼓励覆盖尚未充分覆盖的 branch、anchor 和 motif，并扣除 raw-event overlap。lazy greedy 按边际效用/新增原始事件成本选择；强制 skeleton 单独计入预算。

在 20% 时 C_branch_fair 把 V4 的 44 candidate → 37 final 改为 44 → 41：selection-stage miss 从 7 降到 3，少 4 个；candidate-stage miss 仍为 24，没有改善。

## 11. Mathematical formulas -> code variable mapping

- `w_prop(e)=relation_weight*exp(-age/tau)/(1+alpha*frequency+gamma*fanout)` → `CleanPropagationBuilder` 的 `relation_weights/tau_ns/alpha/gamma` 与 `PropagationEdge.weight`。
- `root_score` 的 source、relation/path、anchor 项 → `RootCandidate.source_support/relation_diversity/path_diversity/anchor_support/root_score`。
- `verification=H(backward_support,forward_support)` → `harmonic_verification()` 和 `ForwardSphere.verification_score`。
- `cost(unit)=|unique raw_event_ids|` → `EvidenceUnit.raw_event_cost`。
- `F(S)` 的 relevance/branch/anchor/motif/verification/redundancy 项 → `BranchFairConfig.lambda_*` 与 `LazyGreedySelector.marginal()`。
- `Delta F/cost` → lazy heap 的 `ratio`；每次选择后的重算由 `utility_recomputes` 记录。
- strict temporal demand 与最小 skeleton → `TemporalDemandPair`、`TemporalReachabilityPreserver.preserve()`。

## 12. Unit tests

Phase 2 相关 36 个测试通过，覆盖：clean propagation 的方向/时间过滤、RR root 与固定 seed、forward sphere、motif raw cost、严格时间 preserver、branch fairness 的 diminishing return/小分支/去重成本/确定性、统一预算、在线 runner 无 GT import/CLI，以及 candidate 增量保护。最终完整仓库测试为 **672 passed in 13.56s**；基线改动前为 636 passed。

## 13. Candidate ablation

20% candidate-stage：V0 为 41/68；V4/B/C 为 44/68；D/E/F/G/H 仍为 44/68。也就是说 Phase 1 已经增加 3 个，而 Phase 2 的 RR、forward、motif、preserver 都没有再增加攻击 candidate。candidate recall 最高仍是 64.71%，没有超过 44/68。

## 14. Selector ablation

20% 最终节点：V4=37，B_normalized=37，C_branch_fair=41，F_motifs=40，G/H=41 但不可行。单纯 ECDF 归一化没有收益；收益来自 branch-fair objective。

C 相比 V4 恢复 4 个且不丢失已有节点：Scenario 06 的 `FFF277E0-39AD-11E8-BF66-D9AA8AFF4A69`；Scenario 13 的 `042ADADF-...`、`2CA83801-...`、`E0C1A46B-...`。

## 15. Budget sweep

| Variant | 5% final | 10% final | 20% final | 30% final | 20% strict paths | 可行 |
|---|---:|---:|---:|---:|---:|---|
| V0 legacy | 36 | 37 | 37 | 37 | 304 | 是 |
| V4 Phase 1 | 36 | 37 | 37 | 37 | 304 | 是 |
| B normalized | 36 | 37 | 37 | 37 | 304 | 是 |
| C branch fair | 39 | 41 | 41 | 41 | 308 | 是 |
| D reverse | 36 | 37 | 37 | 37 | 304 | 是 |
| E forward | 36 | 37 | 37 | 37 | 304 | 是 |
| F motifs | 39 | 39 | 40 | 41 | 307 | 是 |
| G preserver | 41 | 41 | 41 | 42 | 310 | 否 |
| H full | 41 | 41 | 41 | 42 | 310 | 否 |

C 在 5%/10% 的节点召回仍有效，但 strict paths 分别为 225/251，低于 V4 的 243/292；20% 才反超为 308 vs 304。因此低预算存在路径证据回归，不能把节点收益解释成全面胜出。预算 sweep 使用单次 30% greedy trajectory 的前缀；这是确定且高效的工程策略，但多事件 motif 恰好跨预算边界时不完全等价于四次独立 knapsack，结论必须按该限制理解。

## 16. Per-scenario metrics

20% 下：

| Scenario | V4 candidate/final | C candidate/final | C PDF关键事件 | C完整PDF路径 | C strict paths |
|---|---:|---:|---:|---:|---:|
| 06 | 6/4 | 6/5 | 3 | 0 | 8 |
| 12 | 28/28 | 28/28 | 7 | 2 | 288 |
| 13 | 10/5 | 10/8 | 1 | 0 | 12 |

Scenario 06 的 final 改善 1 个；Scenario 12 的 28/39 candidate 没有改善，final 也已饱和于 candidate；Scenario 13 的 candidate 不再增加，但 final 从 5/23 提到 8/23。收益出现在两个场景，因此 selector 不是单场景偶然，但 candidate-stage 仍失败。

## 17. Path/reachability metrics

C 在 20% 保留 11/13 个 candidate PDF 关键事件、2/2 条 candidate 完整 PDF 路径、308/327 条严格时间路径（94.19%）。V4 对应 10/13、2/2、304/327（92.97%）。分场景上 C 在 Scenario 12 比 V4 少 2 条 strict paths（288 vs 290），由 Scenario 06 和 13 的增益抵消后 aggregate 增加 4 条。

Preserver 将 strict paths 提到 310/327（94.80%），但没有增加完整 PDF 路径且违反 per-query 预算。因此它证明了 temporal demand skeleton 的功能性，而没有证明预算内优势。

## 18. Runtime/RSS/profile

9 个 query 的阶段均值/p95：candidate build 0.114/0.304 s，RR 0.125/0.237 s，forward 0.500/0.598 s，motif 0.00025/0.00079 s，preserver 0.075/0.236 s，selector 29.05/92.06 s，总在线 56.55/157.26 s。峰值 RSS 为 7,901,691,904 bytes（约 7.36 GiB）。

profile 明确显示瓶颈是 branch-fair selector，而不是 RR/forward/motif：大量 edge unit 的 lazy heap 重算在大 query 上成本高。相较 Phase 1 约 6.38 GB RSS，本实验内存也更差。下一步应做分支内 top-k 预筛、稀疏 coverage state、增量预算 checkpoint，以及避免每 query 重建整小时图。

## 19. Ground Truth isolation test

在线 runner 的 argparse 没有 Ground Truth 参数，import graph 也没有 ORTHRUS/PDF loader；`canonical_online_bytes()` 会拒绝任何包含 `groundtruth`/`ground_truth` 键的在线 artifact。测试解析在线 runner AST，验证不存在 GT import 和 GT CLI option。只有独立 evaluator 在 `online-results.json` 冻结后加载标签。

冻结证据：`online-results.json` SHA-256 为 `fd6a151e5b1126cfd9bf0439cdc0e1ada32615a420690e3268d05e1a051ac7ca`；离线 evaluation 为 `ae58bc761b7dacce0c514142fc25eba9c81fa70427ff6ecff2ae1066a6b59f33`。PDF 绑定文件为仓库 DARPA E3 PDF；hash 不匹配时 loader fail closed。

## 20. Negative results

- RR/forward 增加了事件和 root/sphere，但新增攻击 candidate 为 0。
- Scenario 12 的 11 个 candidate miss 恢复 0 个；多数 miss 没有合法时间路径。
- normalized score 单独使用没有任何 final recall 收益。
- motif 不优于 edge-only branch fairness，应删除或保留为研究开关。
- preserver 在小 query 上溢出预算，只能作为 optional mode。
- C 在 5%/10% 的 strict path retention 明显低于 V4。
- selector p95 92.06 s、峰值约 7.36 GiB，不满足性能升级条件。
- benign-like candidate explosion 尚未建立独立探针集证明；只能说当前增量 guard 将每 query 新事件限制在 50–2000，不能把它包装为 Gate 已通过。

## 21. Final recommendation

结论对应 Gate 选项 C、D、E：**只保留 Branch-Fair Selector 作为下一阶段优化方向；new search 当前无效，motif 记录为负结果，preserver 仅保留 optional。**

如果必须从本轮选择一个最好算法，选择 **C_branch_fair（V4 candidate + ECDF + branch-fair lazy greedy，不含 RR/forward/motif/preserver）**。它是唯一在预算可行的前提下，把 20% final recall 从 37/68（54.41%）提高到 41/68（60.29%），并把 strict paths 从 304 提到 308 的方案。

但它没有突破 candidate ceiling：candidate-stage miss 仍为 24；它只把 selection-stage miss 从 7 降到 3。加之低预算 path regression 和高 selector 成本，**暂不设为默认算法**。优先优化 selector 性能与低预算 path-aware fairness；candidate 重构需基于身份别名、跨日/跨主机关联或告警覆盖改进重新设计，而不是继续扩大固定深度。
