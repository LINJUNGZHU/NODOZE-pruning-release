# KAIROS-MOSAIC：CADETS E3 架构实验与结果

日期：2026-09-15
状态：完成去泄漏复跑与消融；**最终保留 A_rasp，不把 KAIROS-MOSAIC 设为默认算法**

## 1. 最终结论

严格移除 Track A 对旧 V4 candidate set 的回注后，KAIROS-MOSAIC 的新增检索模块没有突破关键边 candidate ceiling：三场景合计，K3、K4、K5、K6 都只覆盖 PDF partial-positive GT 中的 **10/20 条已知关键边**，完整 PDF 路径均为 **0/7**；只有 short+long memory 把攻击节点从 43/75 微增到 44/75。因此此前“R2 target proposal 恢复 8 条边、推荐 R2+S1”的结论是候选泄漏造成的混杂，现已撤回。

本轮可支持的最简结论只有两点：

1. KAIROS event-level loss field 是最有用的原生输入，但它仍只提供有限的候选覆盖；queue 和 summary 没有独立提高已知关键边覆盖。
2. `relation_round_robin`（S1）在不改变已知 TP 的情况下，把 aggregate projected edges 从 265,839 降到 249,353（-6.20%）；这是冗余控制现象，不足以构成优于 A_rasp 的新算法。

最终算法选择：**继续使用 A_rasp**。KAIROS-MOSAIC 保留为研究/负结果分支；inverse、target、long-history、corridor、多目标 selector 和 safe deletion 均不进入默认方法。

## 2. 实验对象、Track 与 Ground Truth

- 数据集仅为 DARPA TC E3 CADETS，本地数据库包含 39,239,389 个原始事件。
- 场景分别为 CADETS 06、12、13，不把三天合并为一个查询。
- Track A：读取冻结 incident 的 `seed_event_ids`，KAIROS 只提供 evidence prior。旧 `candidate_sets.V4` 不再进入在线候选构造。
- Track B：只使用 KAIROS native evidence，不注入 ORTHRUS/PDF 标签或人工攻击节点。
- 攻击节点标注只来自 PIDSMaker/ORTHRUS E3-CADETS ground truth。
- 关键边与严格路径来自本地 DARPA PDF manifest，明确标记为 `PARTIAL_POSITIVE_GT`。

PDF manifest 不是完整负例全集，因此只能报告 `known_TP`、`known_FN`、`known_recall`、`unlabeled_output_edges`、RawEvents 和 ProjectedEdges；不能把未标注边称为 FP，也不能正式报告 precision、FPR 或与 DepImpact Table 5 完全等价的 FP。

## 3. Phase 2 基线冻结

冻结的 Phase 2 结果保持不变：V0 candidate/final 为 41/68、37/68；V4 为 44/68、37/68；C_branch_fair 为 44/68、41/68。Reverse Reachability 和 Forward Sphere 没有超过 44/68，motif 没有稳定优于 edge-only branch fairness，hard reachability preserver 存在小预算不可行；branch-fair selector 是主要性能瓶颈。

Phase 2 online SHA-256 为 `fd6a151e5b1126cfd9bf0439cdc0e1ada32615a420690e3268d05e1a051ac7ca`，offline evaluation SHA-256 为 `ae58bc761b7dacce0c514142fc25eba9c81fa70427ff6ecff2ae1066a6b59f33`；基线报告记录当时全仓为 672 tests passed。本轮最终全仓回归为 716 tests passed。

这些旧实现和负结果均保留。本轮没有用新实验覆盖或重解释 Phase 2；由于当前 ORTHRUS 分母已更新为 75 个节点、查询聚合方式也不同，44/68 与 43/75 不能直接按绝对数量判胜负。

## 4. KAIROS 原生复现

冻结模型 SHA-256：`367961164b17c9013f4428616a73623dbe634a828fa069de27ccb1ea8f55d66b`。运行环境为 PyTorch 2.4.1+cu124、RTX 3090。day 12 重建 93 个窗口，用时 369.57 秒；day 13 重建 68 个窗口，用时 239.65 秒。

官方 day-6/day-7 evaluator 的复现结果为 TN=174、FP=1、FN=0、TP=4、precision=0.8、recall=1.0、F1=0.8889。无标签 queue builder 在 day 6 得到同一条 5-window queue，score=1077.946。day 12 得到一条 15-window queue；day 13 在固定 β=100 下没有 selected queue。

需要区分两个事实：day 13 的官方二值 queue 决策是 detector miss；但连续 event loss field 仍存在异常分数事件，所以 K0 可以形成候选。报告 K0 结果不等于宣称 KAIROS 在 day 13 产生了官方告警。

重建脚本在本轮重建完成后增加了 seed=0、确定性开关、精确窗口完成标记和 stale-output 防护，供后续重建使用。当前 frozen reconstruction manifest 是旧格式，只记录模型 hash、窗口数和耗时，不声称已经包含新增的确定性字段或逐窗口 hash。

## 5. Native mapping 与 K0/K1/K2 定义

adapter 保留 loss、percentile、queue、summary membership，不将 KAIROS 压成 ORTHRUS alert。映射按 exact identity、精确 `(src,dst,relation,timestamp)`、有界确定性容差依次执行；ambiguous 直接拒绝。

| 场景 | native events | exact mapped | ambiguous | unmapped | mapping rate | 唯一映射事件 | mapped anomaly | mapped queue | summary scaffold |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 06 | 276,951 | 123,097 | 80,281 | 73,573 | 44.45% | 122,936 | 97,830 | 29,496 | 595 |
| 12 | 493,640 | 196,343 | 71,319 | 225,978 | 39.77% | 196,343 | 111,399 | 102,916 | 543 |
| 13 | 120,647 | 73,521 | 34,701 | 12,425 | 60.94% | 73,521 | 73,521 | 0 | 0 |

K0 是全日连续 loss field 中映射成功的 anomaly events，不只取 selected queue；exporter 强制指定 `--day`，不能静默退回只读取 selected-queue windows。K1 是 selected queue；K2 是每个 `(queue,src,dst,relation)` 的最高 loss 去重 scaffold，因此 K2 不再伪装成 K0 的副本。

## 6. 指标对齐

每个输出同时保留两种成本：

- `raw_event_count`：可回放的原始审计记录数。
- `projected_edge_count`：按 `(src,dst,normalized_relation,15-minute temporal group)` 合并的 DepImpact-compatible evaluation edges。

ProjectedEdges 只是 metric-aligned projection；由于攻击、GT 完整性、POI condition 和具体投影规则均未与论文表格完全统一，不能把下面的数值直接写成“优于 DepImpact/NoDoze”。

## 7. K0–K6 与 Candidate Retrieval 消融

Track A、Track B 的质量结果完全相同。原因不是 Track B 自动获得了人工 POI，而是严格去掉 V4 回注后，Track A 的冻结 seed 没有贡献独立的最终 target proposal；两条轨道最终由相同 KAIROS evidence 决定。它是一个负结果。

三场景 aggregate（分母：20 条 PDF 已知关键边、75 个 ORTHRUS 攻击节点、7 条 PDF 路径）：

| 层 | 内容 | known edge TP | attack node TP | complete paths | RawEvents | ProjectedEdges |
|---|---|---:|---:|---:|---:|---:|
| K0 | event loss | 10/20 | 38/75 | 0/7 | 282,746 | 199,764 |
| K1 | selected queues | 9/20 | 38/75 | 0/7 | 132,251 | 110,666 |
| K2 | summary scaffold | 8/20 | 26/75 | 0/7 | 1,138 | 1,138 |
| K3 / R0 | event+queue+summary | 10/20 | 43/75 | 0/7 | 392,800 | 297,345 |
| K4 / R1 | + source-aware inverse | 10/20 | 43/75 | 0/7 | 392,827 | 297,372 |
| K5 / R2 | + target-conditioned proposal | 10/20 | 43/75 | 0/7 | 451,899 | 331,533 |
| K6 / R3 | + short+long memory | 10/20 | 44/75 | 0/7 | 464,424 | 340,481 |
| R4 | + causal corridor | 10/20 | 44/75 | 0/7 | 464,424 | 340,481 |

由此得到：

- event-level loss 最有价值：K0 为 10/20，优于 queue 的 9/20 和 summary 的 8/20。
- queue 对 K0 没有增加关键边，但 K3 相比 K0 增加 5 个攻击节点。
- inverse 在与后续通道隔离的图上只增加 27 raw/projected，没有增加任何已知攻击边、节点或路径。
- target proposal 增加 59,072 raw / 34,161 projected，没有增加任何已知关键边、节点或路径；target-aware ranking 没有找回 global score 低的已知攻击边。
- short+long memory 分别得到真实 short/long 命中，增加 12,525 raw / 8,948 projected，新增 1 个攻击节点，但没有恢复关键边或完整路径；这是有限 node-context 信号，不足以通过主要收益 gate。
- corridor 没有新增候选或路径；当前 anchor/component 结构没有产生有效的 compatible component pair。

Candidate ceiling 仍为 10/20，故 candidate FN 为 **10**，并未从 K3 到 R4 下降。

### Rare long-gap 专项

K6 的 12,525 个独立新增事件按每个事件最近的有效 interaction gap 互斥分桶；所有桶的 PDF known GT recovery 都为 0：

| gap | candidate growth | known GT recovery | unlabeled growth |
|---|---:|---:|---:|
| <1 s | 589 | 0 | 589 |
| 1–10 s | 78 | 0 | 78 |
| 10–60 s | 106 | 0 | 106 |
| 1–10 min | 767 | 0 | 767 |
| 10–60 min | 763 | 0 | 763 |
| >1 hour | 10,222 | 0 | 10,222 |

81.61% 的增长来自 >1 hour 历史，但没有找回已知关键边。这直接支持“long-gap 当前主要引入未标注历史上下文”的负结论；新增的 1 个 ORTHRUS 节点不能证明关键因果恢复。

### 分场景 ceiling

| 场景 | GT edge / node / path | R0 TP edge / node / path | R2 TP edge / node / path | R2 Raw / Projected |
|---|---:|---:|---:|---:|
| 06 | 6 / 8 / 2 | 3 / 3 / 0 | 3 / 3 / 0 | 143,533 / 99,605 |
| 12 | 9 / 43 / 3 | 6 / 35 / 0 | 6 / 35 / 0 | 209,684 / 162,748 |
| 13 | 5 / 24 / 2 | 1 / 5 / 0 | 1 / 5 / 0 | 98,682 / 69,180 |

## 8. S0–S5 选择与 Safe Deletion

| 选择器 | known edge TP | attack node TP | complete paths | RawEvents | ProjectedEdges |
|---|---:|---:|---:|---:|---:|
| S0 legacy relevance | 10/20 | 43/75 | 0/7 | 371,540 | 275,028 |
| S1 relation round-robin | 10/20 | 43/75 | 0/7 | 371,540 | 257,233 |
| S2 multiobjective, no concavity | 0/20 | 5/75 | 0/7 | 3,126 | 1,230 |
| S3 + concavity | 0/20 | 18/75 | 0/7 | 15,367 | 12,622 |
| S4 + path prize | 0/20 | 18/75 | 0/7 | 15,367 | 12,622 |
| S5 + safe deletion | 0/20 | 18/75 | 0/7 | 15,367 | 12,622 |

S1 当前实现是 relation round-robin，不应称为真正的 branch-fair/C_branch_fair。它在相同 raw-event 数下减少 17,795 条 projected edges（6.47%），但没有提高边、节点或路径质量。

S2–S5 的内部 objective 与攻击证据严重错位。以 S5 为例：candidate FN=10，selection 又增加 10 个 FN，最终 known FN=20。修正 soft-demand witness 语义后 S5 相对 S4 没有删除任何边；safe deletion 在本次场景中没有独立收益。

Path prize 没有信号，因为候选阶段没有形成一条完整 PDF path。虽然 reducer 已增加 PathBundle 原始 event witness 检查，但本次数据不能验证其实际收益。多目标 selector 没有解决 Phase 2 的低预算 path regression，反而丢失了全部已知关键边。

## 9. FN-vs-ProjectedEdges 主问题

本轮不存在 FN=0、FN≤1、FN≤2、90% recall 或 95% recall 的可行点。最高 candidate/final known recall 都只有 50%（10/20），所以“达到 FN=0 所需多少边”答案是：**不可达，不存在可报告的 ProjectedEdges 或 RawEvents**。

Scenario 12 的结果尤其明确：

| 输出 | known TP/FN | attack nodes | RawEvents | ProjectedEdges |
|---|---:|---:|---:|---:|
| R2 candidate | 6/3 | 35/43 | 209,684 | 162,748 |
| S1 | 6/3 | 35/43 | 171,999 | 127,184 |
| S5 | 0/9 | 15/43 | 5,236 | 4,160 |

因此 Scenario 12 没有在保持攻击质量的同时从数万边降到百/千级；4,160 projected edges 的点丢掉了全部 9 条已知关键边，不能作为成功压缩结果。

逐检查点 frontier 已保存在 `evaluation.json` 的 `fn_vs_projected_edges`，但没有任何 checkpoint 越过上述 candidate ceiling。

## 10. Runtime、MR 与 RSS

| Track/场景 | rows materialized | MR | retrieval (s) | selector p50 (s) | selector p95 (s) | peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| A06 | 180,288 | 0.4595% | 64.76 | 6.37 | 6.49 | 613 MiB |
| A12 | 248,176 | 0.6325% | 71.54 | 8.82 | 8.84 | 948 MiB |
| A13 | 133,223 | 0.3395% | 18.91 | 3.66 | 3.69 | 430 MiB |
| B06 | 180,288 | 0.4595% | 65.99 | 5.94 | 5.96 | 629 MiB |
| B12 | 248,176 | 0.6325% | 69.56 | 8.76 | 8.80 | 947 MiB |
| B13 | 133,223 | 0.3395% | 18.89 | 3.81 | 3.81 | 430 MiB |

relation selector 的队列实现从 `pop(0)` 改为 `deque.popleft()` 后，六个 selector p95 均低于 10 秒，但没有达到大型 query p95<5 秒目标；完整 retrieval 更远高于普通 query 2 秒目标。最大 RSS 约 948 MiB，尚不能证明满足“不超过 Phase 1 25%”的 gate。

`/proc/self/io` 受 page cache 影响，六次读字节差异很大，不作为算法优劣证据；逻辑成本使用 rows、MR、RawEvents 和 ProjectedEdges。

## 11. GT 隔离、确定性与审计修复

外部 config 和 KAIROS evidence payload 现在使用严格字段 allowlist，而不是只依赖 GT 关键字黑名单；evidence 顶层、mapping audit、source hash 和每个 event row 都检查精确 schema。Track A legacy artifact 经过 adapter 后只有 `scenario + seed_event_ids` 跨越在线边界，Track B 从 CLI 层拒绝 incident input。最终在线结果在序列化前还会递归拒绝 truth、label、malicious、attack、ORTHRUS、CAPTAIN、PDF/DepImpact GT 和 oracle 字段。在线 runner 不导入 evaluator 或 GT loader；离线 evaluator 只在 online JSON 冻结后读取 ORTHRUS/PDF。

本轮还修复了以下会污染结论或审计的问题：

- Track A 只读取 seed IDs，不读取 V4 candidate set；incident artifact 纳入 hash。
- decision hash 在性能采样前冻结，并绑定 evidence/config、allowlisted incident seed、23 GB SQLite 的完整 content SHA-256、mapping audit 和 retrieval audit；性能波动不改变 decision hash。
- K0 覆盖全日连续 loss field，K2 为真正去重 scaffold。
- inverse 与 long-short 模块被接入生产 runner，不再只是未调用的类。
- representative prefilter 使用 branch、anchor、demand 三类 lane 的 union。
- corridor projected edge 使用 canonical edge identity，并执行时间/兼容性 gate。
- reducer 删除前检查每个 temporal PathBundle 是否仍保有完整 witness。
- evaluator 在 projected-edge 集合上求交，而不是先按 raw event ID 求交，并显式输出 known projected TP 和 unlabeled raw/projected output。

Track A/B 的事件选择结果相同，但 decision hash 因 Track A 额外绑定 allowlisted incident seed 输入而有意不同；content hash 还会随运行时 telemetry 变化。SQLite content SHA-256 为 `719f97dafb642f49b0cffff6deaeb42138386521cfc2cf27539d6d5ae6a81abf`，runner 会重新计算并拒绝不匹配的声明值。当前离线 evaluation content SHA-256 为 `e70a7ad567b7c59ff0e5bd46d383510eec61e8dd29a9820090092a1fcdc1e5b1`。

在当前代码路径和测试覆盖范围内未发现 GT leakage。这里的结论是实现级隔离，不是对所有未来外部数据处理过程的形式化证明。

## 12. 与 A_rasp、ORTHRUS、DepImpact/NoDoze 的关系

### KAIROS 是否比 ORTHRUS 提供更高 candidate ceiling？

没有证据支持。A_rasp Phase 2 的 ORTHRUS-conditioned V4 是 44/68 节点；当前 KAIROS K3 为 43/75，加入 short+long memory 后 R4 为 44/75，关键边仍为 10/20。分母和查询协议不同，不能直接做数值大小比较；按各自 recall，KAIROS 58.67% 也未显示优势。Track A 的 ORTHRUS seed 没有带来独立增益，Track A/B 事件输出相同。

### 哪些比较 apples-to-apples？

- 本报告内部 K0–K6、R0–R4、S0–S5：相同数据库、GT、projection 与场景，属于同协议比较。
- Track A 与 Track B：可比较输入条件的影响，但本轮结果重合；Track B 仍不能假装为 POI-conditioned 方法。
- 与 Phase 2 A_rasp：只能作为同项目、不同分母/聚合协议的参考，不是严格 apples-to-apples。
- 与 DepImpact/NoDoze Table 5：只有 ProjectedEdges/FN 的概念对齐；攻击集合、完整 edge GT、POI 条件和投影实现未统一，因此只是 metric-aligned reference，不能宣称更好。
- Route C 的 9/9 oracle agreement、36.39 MB 对 74.29 MB 属于旧 A_rasp candidate contract 下的物化实验，不能移植为 KAIROS-MOSAIC 的成绩。

## 13. 负结果与下一步

| 模块 | 独立收益 | 决定 |
|---|---|---|
| KAIROS continuous event loss | 原生输入中最高关键边覆盖 | 保留为研究 sensor |
| queue | +5 nodes（K0→K3 联合），关键边不增 | 保留 ablation |
| summary scaffold | 单独仅 8/20 | 不作主输入 |
| inverse source coverage | 0 edge / 0 node / 0 path gain | 降级 diagnostic |
| target-conditioned proposal | +59,071 raw，0 known TP gain | 默认关闭 |
| short+long memory | +1 node；0 edge / 0 path gain | 默认关闭，保留专项实验 |
| causal corridor | 0 candidate/path gain | 默认关闭 |
| relation round-robin | 同质量下 projected -6.47% | 可作为工程优化继续验证 |
| robust multiobjective | known edge 10→0 | 失败，不能发布 |
| path prize | 无有效 path signal | 未验证 |
| safe deletion | 0 edge deletion | 未通过质量 gate |

下一轮只值得做三件事：首先从 KAIROS vectorization 保存原始 CDM event UUID，降低 ambiguous/unmapped；其次把 component 改为 queue 内 anomaly-connected subcomponents，使 corridor 有真正 demand pairs；最后重新设计 label-free objective，使其在 development split 上至少不低于 S1 的关键边代理与严格 witness，再做 leave-one-scenario-out。没有通过独立增益 gate 的模块不应继续叠加。

## 14. 最终 Gate

| Gate | 结果 |
|---|---|
| KAIROS day-6 官方队列复现 | PASS |
| online/offline GT 隔离 | PASS |
| RawEvents / ProjectedEdges 双口径 | PASS |
| candidate FN / selection FN 分解 | PASS |
| selector p95 < 10 s | PASS |
| selector p95 < 5 s | FAIL |
| candidate FN 低于 K3 | FAIL（始终 10） |
| 达到 FN=0 或 ≥90% known recall | FAIL |
| Scenario 12 保质降至百/千级 | FAIL |
| inverse / target / short+long / corridor 的关键边或路径独立收益 | FAIL（short+long 仅 +1 node） |
| multiobjective 解决 path regression | FAIL |
| safe deletion 在合格质量图上有效 | FAIL |
| 可与 DepImpact/NoDoze 完全同表比较 | FAIL |

最终决定：**默认算法仍为 A_rasp；不选择完整 KAIROS-MOSAIC，也不再推荐 R2+S1。**

## 15. 复现入口与产物

代码入口：

- `scripts/reconstruct_kairos_frozen_days.py`
- `scripts/build_kairos_native_queues.py`
- `scripts/export_kairos_evidence.py`
- `scripts/run_kairos_mosaic.py`
- `scripts/evaluate_kairos_mosaic.py`

结果目录：`/root/NODOZE-pruning-release/output/kairos-mosaic-20260915/`，包含 reconstruction、day 6/12/13 queue、evidence、六个 Track A/B online JSON 和 `evaluation.json`。方法来源与借鉴边界见 [KAIROS-MOSAIC design](kairos-mosaic-design.md)。
