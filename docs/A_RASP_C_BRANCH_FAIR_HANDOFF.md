# A_rasp、A_rasp-PBR 与 C_branch_fair：当前实验交接

更新日期：2026-09-21（Asia/Shanghai）
当前正式结果：`COMPLETED`

## 1. 当前主线

项目现在比较三个剪枝器：

- `A_rasp`：基于稀有度、严格因果方向、restart propagation 和路径 bundle 的基线。
- `A_rasp-PBR`：先生成较小的 A_rasp 基础图，再按 detector-local POI 对救援断裂严格时序桥。TRACE 使用 10,000-event 基础图和最多 2,000 条 rescue；CADETS 的实际最优点只比 842-event 基础图增加 3 条事件。
- `C_branch_fair`：把公共候选中的 anchor/forward/backward/control branch provenance 作为覆盖对象，用 diminishing-return lazy-greedy 保持不同调查分支。

三者共享同一 detector 输出、公共候选、mandatory POI proxy、投影规则和 raw-event 上限。ORTHRUS 只在在线决策密封后加载，用于离线正例评价，不参与 detector、candidate 或 selector 调参。

## 2. TRACE E3 最终协议

### 数据与 detector

- 本地语料只覆盖 `2018-04-13 09:56–17:09`，不是官方 TRACE 多日训练划分。
- 协议名：`local-single-day-chronological-25-10-65`；前 25% 窗口训练、后 10% 验证、余下 65% 测试。
- KAIROS/PIDSMaker 完整执行 construction、transformation、featurization、feature inference、batching 和 12 epoch training；未运行 label-aware evaluation。
- 最终模型：`model_epoch_11`。
- KAIROS 原生规则：窗口内 `loss > mean + 1.5 × population_std`；按 published training-IDF 连接 queue；固定 queue threshold `20`。
- 17 个 selected queues 产生 10,992 个 UUID POI。
- 10,590 个 anomalous `(src index, dst index, timestamp)` 键全部映射成功，密封为 19,550 个 exact raw event UUID；无 unmapped key。

### POI 与路径口径

KAIROS POI 首先决定场景是否可评价：`sealed KAIROS POI ∩ ORTHRUS positive node`。只有至少一个端点属于这个交集的严格时序攻击路径才进入分母。候选接纳召回单独报告，不能替代 detector recall。

旧实现只传 node+window，builder 会向窗口前后扩展而排除窗口内部异常边，导致 10,992 个 POI 只有 730 个进入候选。最终实现把 KAIROS 异常边作为 exact event anchor；结果为 10,992/10,992 POI 全部进入 20,000-event 公共候选。

参数：

- candidate cap：20,000 raw events；strict depth 8；control depth 2；common cause enabled。
- selector cap：12,000 raw events；PBR 分配为 10,000 基础 + 最多 2,000 rescue。
- projection：`DEPIMPACT_COMPATIBLE`，900 秒 merge window。
- mandatory proxy：每个 detector POI 至少一个共同候选内邻接事件，共 8,145 个 unique proxy events。
- C checkpoint：mandatory-only 8,145，以及最高约 12,000 raw events。

## 3. Detector 与候选有效性

| ORTHRUS 场景 | 攻击节点 | KAIROS 命中 | Detector attack-node recall | 进入候选 |
|---|---:|---:|---:|---:|
| Firefox 0410 | 11 | N/A | N/A | N/A |
| Phishing executable 0413 | 11 | 5 | 45.45% | 5/5 |
| Pine 0413 | 14 | 14 | 100% | 14/14 |

Firefox 0410 不计分，因为本地语料没有 4 月 10 日数据，不能把它记成 detector miss。两个可评价场景按场景求和为 19/25（76%），但该数字不是跨场景去重后的全局 recall。

公共候选：

| 指标 | 结果 |
|---|---:|
| Raw events | 20,000 |
| Projected edges | 10,911 |
| Detector POI candidate coverage | 10,992/10,992 = 100% |
| Candidate elapsed | 2.400 s |
| Store edge queries | 10 |
| Peak RSS | 2,178,932 KiB（约 2.08 GiB） |
| Stop reason | `CAP_REACHED` |

### 从 POI 到最终攻击节点的具体漏斗

| 层级 | Phishing 0413 | Pine 0413 | 说明 |
|---|---:|---:|---|
| ORTHRUS 攻击节点 | 11 | 14 | 仅离线评价使用 |
| KAIROS POI 中的攻击节点 | 5 | 14 | detector 命中 |
| Candidate 中的攻击 POI | 5 | 14 | 两个场景均为 100% 接纳 |
| A_rasp 最终攻击节点 | 5 | 14 | 总输出节点 11,215 |
| A_rasp-PBR 最终攻击节点 | 5 | 14 | 总输出节点 11,148 |
| C mandatory-only 最终攻击节点 | 5 | 14 | 总输出节点 10,994 |
| C 最高质量点最终攻击节点 | 5 | 14 | 总输出节点 10,994 |

两个可评价场景按场景计数是 19 个攻击 POI；去重后是 18 个，因为两个 ORTHRUS 场景共享 1 个攻击节点。相应地，两个场景的 ORTHRUS 节点总和是 25，去重后是 24。这里“最终攻击节点”指输出图仍包含的 ORTHRUS-positive KAIROS POI，不是输出图的总节点数。

## 4. TRACE E3 最终结果

### 在线规模与时间

| 方法 | Raw events | Raw materialization ratio | Projected edges | Selector time |
|---|---:|---:|---:|---:|
| A_rasp | 12,000 | 60.00% | 8,986 | 80.607 s |
| A_rasp-PBR | 11,232 | 56.16% | 9,965 | 218.523 s pipeline；58.591 s rescue |
| C_branch_fair（mandatory-only） | 8,145 | 40.73% | 8,145 | 同一 trajectory |
| C_branch_fair（最高质量点） | 11,997 | 59.99% | 9,188 | 35.855 s end-to-end |

PBR 共接收 9,219 个由 KAIROS exact anomalous events 派生的局部 POI 对：7,979 对已由 10k 基础图连通，1,240 对需要救援并全部恢复。由于桥之间共享事件，1,240 个 bundle 实际只新增 1,232 个 unique raw events，未用满 2,000 上限。PBR pipeline 时间包含 10k A 基础选择、证据侧车和 rescue，不能只报告 58.591 秒 rescue。C 的 10,000/12,000 projected targets 落在同一个实际点，因为在 11,997 raw / 9,188 projected 后没有正边际收益可继续选择。

### Phishing executable 0413

参考子图只有 1 条边、1 条 POI-to-POI/anomaly path。A、PBR、C mandatory-only、C 最高质量点均为：

- attack POI node retention：5/5 = 100%。
- reference-edge retention：1/1 = 100%。
- canonical path retention：1/1 = 100%。
- strict temporal reachability retention：1/1 = 100%。

### Pine 0413

参考子图有 10 条边、8 条 POI-to-POI/anomaly paths。

| 指标 | A_rasp 12,000 | A_rasp-PBR 11,232 | C 8,145 | C 11,997 |
|---|---:|---:|---:|---:|
| Attack POI node retention | 14/14 = 100% | 14/14 = 100% | 14/14 = 100% | 14/14 = 100% |
| Reference-edge retention | 9/10 = 90% | **10/10 = 100%** | 8/10 = 80% | 9/10 = 90% |
| Canonical path retention | 7/8 = 87.5% | **8/8 = 100%** | 6/8 = 75% | 7/8 = 87.5% |
| Strict temporal reachability | 7/8 = 87.5% | **8/8 = 100%** | 6/8 = 75% | 7/8 = 87.5% |

所有有效路径在本实验中都是 POI-to-POI，因此：

- `Anomaly Path` 与 `POI-to-POI Path` 使用上表的 8 条路径。
- `Backward Path`、`Forward Path` 没有 eligible path，应报告 `N/A`，不能报告为 0% 或 100%。
- Path Length：最小 1、median 1.5、最大 2 条边。
- Time Interval：最小 0、median 4.794 秒、最大 214.091 秒。

ORTHRUS 在这里是 partial-positive node ground truth，没有完整负例边标签，因此 precision、FP、FPR、F1 仍为 `NOT_AVAILABLE_PARTIAL_POSITIVE_GT`。

### 与 RQ1–RQ4 的对应关系

- RQ1：已回答 detector attack-node recall、candidate admission recall、attack-node/edge/path retention；没有完整负例，不能计算 oracle precision/FPR。
- RQ2：已回答 raw/projected materialization ratio、candidate RSS 和 store query count；当前存储接口没有记录真实 bytes read 与 rows scanned。
- RQ3：已记录单次 candidate/A/C latency；尚未做多次独立重放，因此不能把单次值写成 p50/p95。
- RQ4：C 有 mandatory-only 与最高质量两个实际 checkpoint，可展示按需规模；当前只有一个可用测试日，不能可靠统计跨 query expansion-round/fallback 分布。

因此，这是一轮已完成且可复现的 TRACE 功能/质量比较，但不是完整的多 query、重复运行 RQ1–RQ4 统计实验。

## 5. CADETS E3 对照结果

CADETS E3 使用 50,000 条公共 candidate raw events，三种方法在同一 POI 与 ORTHRUS-only 离线口径下比较。当前质量最优的 PBR 点如下：

| 方法 | Raw events | Projected edges | 攻击节点 | 参考边 | 严格路径 | 选择耗时 |
|---|---:|---:|---:|---:|---:|---:|
| A_rasp | 842 | 261 | 49/50 | 28/32 | 31/39 | 0.448 s |
| **A_rasp-PBR** | **845** | **264** | **49/50** | **31/32** | **38/39** | A + 3.588 s |
| C_branch_fair 最大点 | 23,973 | 16,931 | 49/50 | 30/32 | 33/39 | 666.422 s |

PBR 只在 A_rasp 基础上增加 3 条 raw events，却多恢复 3 条参考边和 7 条严格路径；相对于 50,000-event candidate，它剪掉 98.31% 的事件。C 在这个数据集上读取量和时间都显著更大，路径恢复仍低于 PBR。

## 6. 明确结论

在当前 TRACE E3、KAIROS POI、ORTHRUS 离线评价协议下：

- **质量最好的是 A_rasp-PBR**：只用 11,232 raw events，就保留 Phishing 1/1 和 Pine 10/10 参考边，并把 Pine 严格路径从 A/C 的 7/8 提升到 8/8。
- **效率最好的是 C_branch_fair mandatory-only**：8,145 raw events、35.855 秒整条 C trajectory，仍保留两个场景全部 19 个攻击 POI，但 Pine 只保留 8/10 边、6/8 路径。
- PBR 的代价是慢：完整 pipeline 218.523 秒，约为 A 的 2.71 倍、C trajectory 的 6.09 倍。

因此若汇报只能选一个并以攻击路径完整性为第一目标，应选 **A_rasp-PBR**。它在 CADETS E3 和 TRACE E3 都取得最高的参考边与严格路径恢复率。若 TRACE 的第一目标是速度与最小读取量，则可选 **C_branch_fair mandatory-only**，但需接受较低的路径恢复率。不能再笼统称 C 为综合最好。

跨数据集的压缩率不能直接排名：CADETS 只有 845/50,000（1.69%），TRACE 为 11,232/20,000（56.16%），主要原因是 TRACE 有 10,992 个 detector POI 和 8,145 个 mandatory proxies，而 CADETS 的 POI 密度低得多。应分别报告每个数据集的告警覆盖、候选规模和路径分母。

## 7. 本轮关键修复

1. 本地 TRACE SQLite 直接导入 PostgreSQL，绕过不支持 Range 的 Google Drive 下载。
2. dense continuous node index 修复 TGN CUDA OOM。
3. KAIROS 原生异常窗口、node POI 与 exact anomalous event UUID 一起密封。
4. detector recall 与 candidate admission recall 分离；评测资格使用全部 sealed detector POI。
5. node anchor 公平接纳，避免高扇出早期 POI 吃满 cap。
6. C selector 不再把 mandatory units 重复送入 greedy queue；mandatory coverage 在初始状态直接登记。
7. TRACE 输出保留 A_rasp、A_rasp-PBR 与 C_branch_fair，并为高基数 KAIROS POI 使用 detector-event-local demand pairs，避免枚举 120,813,072 个全排列对。

## 8. 权威产物与复现

- 最终目录：`output/trace-e3-kairos-poi-runs/trace-e3-kairos-poi-20260918-pbr-v9/`
- 最终评价：`offline/evaluation.json`
- 在线决策：`offline/online-2018-04-13.json`
- KAIROS seal：`detector/kairos-poi-seal.json`
- 结果内容哈希：`bdeae93ad922c5961dac1179f64e6de68588f7e04002c0ec1052813b63099f00`
- 共同候选哈希：`a45ab0915bb21940b51c8acd75414ec4bac5a96a5a348ddbf1a4ffb070073a0e`
- A decision hash：`4a757a16945f6cdeae6f8d0b46fa5d38821b8731e933c854f17b5232b39cd6c9`
- A_rasp-PBR decision hash：`36a1010b95be033a88557b21057a23cc823c1194f3a4128f4c0afc49eedf271f`
- C highest-quality decision hash：`413bef9c29a13f18cb1c28e6cc629c9618c97f28087d76f2f77d9756ab0173aa`
- KAIROS training artifacts：`/root/pidsmaker-artifacts-trace-e3-kairos-localday-v2/`

CADETS E3 权威产物：

- 最终目录：`output/a-rasp-pbr-runs/pbr-20260917T080025Z-02835980/`
- 最终评价：`evaluation.json`
- 在线 seal：`online-seal.json`
- 结果内容哈希：`9062f1f161dac9ecdec8094f0a239c44e53d7da1f1c7b5185655d7efa6e255dc`

复现完整流水线（会复用已完成训练缓存）：

```bash
cd /root/NODOZE-pruning-release/.worktrees/query-adaptive-cadets-e3
RUN=output/trace-e3-kairos-poi-runs/trace-e3-kairos-poi-$(date +%Y%m%d-%H%M%S)
bash scripts/run_trace_e3_kairos_pipeline.sh "$RUN"
```

查看终态：

```bash
jq '{status,stage,detail}' "$RUN/process-status.json"
jq '{status,content_sha256}' "$RUN/offline/process-status.json"
```

只有两个文件都显示 `COMPLETED`，才算整条实验完成。
