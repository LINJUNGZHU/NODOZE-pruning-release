> **增强规则更新**：从单进程匹配扩展为可核验的进程创建链。原公开标注中召回从 3/8 提升至 8/8，1 个进程误报；默认活动事件召回 733/735。TAPAS 静态进程清单的召回另算，默认为 9/44，未达到 90%。[方法、双标注对照和限制](docs/rule-lineage-method.md)。

> **全量大图与深度学习实验**：网页已简化为三步工作台，4 个真实案例最高 188,609 条原始边；提供实际训练的自监督图模型。当前神经模型未优于规则，作为实验选项保留。 [使用说明](webapp/README.md) · [论文依据与实测负结果](docs/deep-graph-method.md)。

> **攻击节点与路径已接入 OPTC 页面**：[判定方法与论文/源码依据](docs/attack-inference-method.md) · [节点准确率、漏检与路径实验](docs/attack-inference-evaluation.md)。默认 POI 在公开标注口径下 TP=3、FP=0、FN=5，Precision=100%、Recall=37.5%；不是独立测试或完整攻击链恢复保证。

> **评分与判定审计更新**：[论文研读](docs/provenance-selection-literature.md)、[方法与证明范围](docs/evidence-selection-method.md)、[含负结果的对照实验](docs/evidence-selection-evaluation.md)。默认保留扩展上下文，可选证据子图；所有判定可下载并重放。

> **OPTC Web 更新**：支持按 Ground Truth 手动设置 POI，频率统计使用全部严格早于 POI 的历史。
> [启动与页面说明](webapp/README.md) · [三个 POI 的真实评估结果](docs/optc-poi-evaluation.md)。

# 稀有度与图扩散融合的溯源图自适应剪枝

**当前默认：[RASP-D q=0 / 20% 边预算](docs/selected-default.md)**。四案例同预算平均攻击事件召回 95.87%；按已有开发结果选型，不是泛化保证。默认命令入口为 `python -m scripts.run_selected_rasp`，网页已同步；旧实验和流式原型保留独立入口。

新增[论文/公开项目参考与排名融合实验](docs/rank-fusion-research.md)：RASP-RRF 提供四案例 64 组同预算对照及逐边排名证据，有部分收益也有显著退步，未替换默认算法。

增量工程实验：[Stream-RASP](docs/stream-rasp.md) 基于动态 PPR 残差维护，支持逐行 CDM 微批读入和版本化逐边决策。当前是原型，不替代离线默认算法；历史回查的后续更新见下一段。

后续新增 [历史回查与攻击事件召回对照](docs/history-recall.md)：`--history` 启用端点分片索引及跨窗口候选恢复；三天在同一绝对保留边上限下比较。可靠续读仍未完成，候选覆盖率和最终攻击事件召回分别汇报。

本项目面向主机溯源图的“依赖爆炸”问题，实现了一条可复现实验链路：流式导入 DARPA TC 数据，统计 POI 发生前的事件频率，以关系感知的 POI 事件为种子进行时间双向图扩散，再用 RDP-Guard（稀扩守链）融合稀有度与扩散支持并完成路径守卫剪枝。

当前可运行实现位于 `tc_pruning/`。主流程不再依赖 KAIROS：可直接输入待调查的 event ID；KAIROS 转换器仅为兼容旧实验保留。POI 不是攻击真值，攻击路径保留率必须使用独立标注评估。

面向 CCF-A 级实证要求的当前保证、可主张边界与后续基线/统计计划见 `docs/CCF_A_EVALUATION_ROADMAP.md`；仓库明确把它作为质量目标，而不是录用保证。

2026-09 新增 [RASP：对比传播与因果分叉剪枝](docs/rasp-method.md)：
重新计算去重复交互偏差的 PPR 与背景对比评分，融合历史稀有度，在硬边预算下成组保留共同原因分叉。
THEIA 和 CADETS 三天使用同配置开发集对照；完整结果、消融与逐边分数支持网页切换。
[上一轮 T-MASS 负结果](docs/t-mass-research.md) 继续保留，不宣称达到顶会水平。运行与展示见
[Web Demo](webapp/README.md)，测试命令为 `PYTHONPATH=. python -m pytest -q`。

## 项目总体架构与流程

```text
DARPA TC 原始溯源事件
        │ 导入
        ▼
SQLite 溯源图（进程、文件、网络节点及其事件边）
        │                         POI 事件 ID
        │                     （检测器或分析员提供）
        └──────────────┬──────────────────┘
                       ▼
             逐告警构建因果候选图
       （方向与时间单调 + 可疑度优先 + 自适应分支）
                       │
                       ▼
 稀有度 + 图扩散 + NODOZE + DEPIMPACT + 行为分段
                       │
                       ▼
                逐告警自适应剪枝
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
       剪枝后的调查图       与独立 UBC 真值比较
                                 │
                                 ▼
                    压缩率、召回率、精度、F1
```

### 输入是什么

系统有三个相互独立的输入：

| 输入 | 内容 | 用途 |
|---|---|---|
| 溯源数据库 `--db` | 一段连续时间内采集的全部系统事件，以及事件涉及的进程、文件、Socket 等节点 | 提供待搜索和剪枝的完整溯源图 |
| POI 文件 `--poi-events` | JSON 数组、含 `event_ids` 的 JSON 对象，或每行一个 event ID 的文本文件 | 多个事件默认属于同一调查；结构化 JSON 可给出有序阶段、事件组和显式时间窗，并按事件关系选择进程侧调查锚点 |
| 兼容清单 `--annotations` | 已有的事件中心告警清单，可来自任意检测器 | 与 `--poi-events` 二选一 |
| 真值文件 `--groundtruth-annotations` | 独立整理的攻击事件、攻击节点，以及可选的完整攻击路径 | 只用于离线评价，不能参与剪枝打分 |

输入不是固定时间段内的所有节点。每个 POI 是一条带时间戳的依赖边 `E=⟨SRC,DST,REL⟩`。系统以完整 POI 事件为锚点执行因果搜索，并根据事件语义选择进程侧调查锚点，而不是无条件使用 `DST`。

告警窗口只表示检测器在哪段数据上产生了告警，不再作为因果搜索的时间边界。当前搜索没有固定小时限制，也没有业务跳数限制：只要边的方向和时间顺序正确、路径可疑度仍达到阈值，就可以继续跨越多天、多阶段扩展。只有找不到符合条件的更早前驱或更晚后继时，才认为到达因果头部或尾部。

### 配置文件

搜索、评分和剪枝参数统一保存在 `configs/tc_pruning.json`，不再通过一长串命令行参数临时设置。CLI 只使用 `--config` 选择一个可复现实验配置。

配置中的 `min_edge_suspicion`、`min_path_suspicion` 和 `min_frontier_relevance` 决定分支是否继续扩展。搜索从 15 分钟局部窗口开始；边界仍存在高相关事件时按倍数扩窗，遇到长时间休眠则通过方向索引跳到最近事件，而不是设置固定调查时间上限。队列优先级融合 rarity、temporal proximity 和局部 fanout；高频实体按时间片分区计算 fanout，避免热点进程一次淹没队列。重复的 `⟨SRC,DST,REL⟩` 事件作为证据保留，但只扩展代表事件。`resource_max_edges`、`resource_max_states`、`resource_max_hops` 和 `resource_timeout_seconds` 默认均为 `null`，只作为显式安全熔断；正常终止条件是 frontier 已无足够重要的因果分支。

### 怎么判断节点是否有害

当前系统不会因为某个节点处在告警时间段内，就直接把它判为有害。节点本身通常只是进程、文件或网络端点，“有害”需要分成两个阶段：

1. **在线怀疑**：任意检测器或分析员给出 POI event ID；事件及其 `DST` 只是可疑种子，不等于已经确认恶意。稀有度、图扩散、行为分段、DEPIMPACT 和路径分数用于判断哪些上下文更值得保留。
2. **离线确认**：实验阶段用独立 UBC/DARPA 真值核对。告警事件与真值攻击事件直接重合时记为 `strong`；只有节点重合时记为 `weak`，不能据此确认该节点有害；完全不重合记为 `none`。只有 `strong` 告警进入主要攻击重建指标。

因此，剪枝输出是供调查的高价值证据子图，不是“恶意节点判决书”。实际部署中仍需结合事件链、进程命令、文件路径、网络目标以及分析员规则判断告警是真攻击还是误报。实验中的真值仅用于验证系统有没有保住正确攻击上下文。

### 输出是什么

`experiment` 命令输出一个 JSON 报告，主要包括：

- `results[]`：每个剪枝比例下的候选图、保留图和实际压缩率；
- `actual_keep_ratio`：真正保留的边比例，压缩率为 `1 - actual_keep_ratio`；
- `alert_aligned_evaluation`：逐告警与独立攻击真值的比较结果；
- `causal_search_policy` 和 `causal_search_config`：本次搜索策略及实际配置；
- `search_diagnostics`：自然找到头尾的路径数、截断路径数和停止原因；
- `poi_seed_policy`：POI 采用关系感知锚点；`READ/RECV/ACCEPT` 从事件主体（归一化边的 `dst`）回溯，`FORK/CLONE` 以新建子进程为评分种子，其余事件从 `src` 主体回溯和评分；
- `depimpact`：10 秒边合并前后规模、数据量特征覆盖率和 LDA 投影向量；
- `behavior`：行为簇数量及实际聚类后端；
- `top_edge_scores`：报告内便于快速查看的前 100 条边；完整边分数不再被这个展示上限截断；
- `score_ledger`：完整边分数账本的位置、行数、高异常边数、候选图摘要和 SHA-256；账本中的每条候选边都记录 rarity、diffusion、path、depimpact、behavior、POI 来源以及各预算的保留决定与理由；
- `path_certificate_status`：区分单链 `valid`、多分支 `valid_forest`、`poi_only`、`candidate_disconnected`、`budget_infeasible` 和 `missing_poi`；
- `prefix_jaccard`、`removed_previous_edges`、`declared_allowed_removed_previous_edges`、`atomicity_churn_slack_edges`：多 POI 前缀的稳定性、声明界限与原子组不可分造成的精确附加界限；
- `score_mass_retained`：当前输出保留的在线重要性质量；
- `causal_path_cover_certificate_valid`、`certificate_topology`、`certificate_branch_count`：区分 singleton、chain 与预先声明的 forest，并给出整个因果路径覆盖是否有效；
- `strict_multistage_certificate_valid`、`stage_path_witnesses`：严格按 `(timestamp_ns, edge_id)` 顺序复核后的单链多阶段因果骨架及证据边；
- `rdp_guard_recommendation`：不查看 Ground Truth、仅依据证书与分数质量选择的最小建议保留点；
- `candidate_context_edge_recall`：剪枝前的因果搜索找到了多少非告警锚点攻击上下文；
- `pruned_context_edge_recall`：最终剪枝图保留了多少真实攻击上下文；
- `conditional_context_edge_retention`：已经进入候选图的真实上下文有多少没有被剪枝误删；
- `pruned_context_edge_precision` 和 `pruned_context_edge_f1`：只有在正负边标签穷尽时才可解释；当前派生参考路径实验不把它们作为论文主指标；
- `reconstructed_paths`：剪枝后仍完整存在的候选因果路径，供后续分析和攻击链展示。

一句话概括：**输入是“完整溯源事件图 + POI 事件”，不是一批预先标成有害的节点；输出是围绕每个 POI 生成的精简调查图和独立真值评估报告。**

## 核心方法

对候选图中的边 `e`，先计算：

```text
rarity(e) = 节点类型、边关系和 (源类型,关系,目标类型) 模式频率的组合稀有度
diffusion(e) = 从有序 POI 事件出发的时间单调、关系感知双向扩散分数
path(e) = 可选的 NODOZE 候选路径重要性
impact(e) = DEPIMPACT 三特征经 KMeans++/LDA 投影后的局部权重
behavior(e) = 长进程中与 POI 同属一个 HDBSCAN 行为簇的相关性

score_raw(e) = diffusion(e) * [wd + wr*rarity(e) + wp*path(e) + wi*impact(e) + wb*behavior(e)]
score(e) = score_raw(e) / max(score_raw)
```

这就是 RDP-Guard 的扩散门控：`diffusion(e)=0` 时，即使事件罕见也不能靠稀有度进入高分区；在相同因果扩散支持下，较稀有的事件仍获得更高优先级。这样保留了攻击链中常见但不可缺少的系统调用桥，同时抑制与 POI 无关的离散稀有噪声。旧独立加权公式仍可通过 `scoring.fusion_mode=additive` 复现实验，但 CADETS 配置使用 `rdp_guard`。

新的 PS-RDP 前缀模式会为每个 POI 独立计算并冻结上述局部分数，再用数值稳定的 `previous + (1-previous)×local` 实现 `1-Π(1-score(e,poi))` 聚合。因此增加 POI 时任何边的累计重要性都不会下降，旧 POI 的分数摘要也不会被重新训练改写。固定预算下，声明换边界限由预算收缩、新增强制证书成本和 `churn_slack_ratio × 预算` 构成；随后用 bitset 有界子集规划器重建可行的旧原子组。声明界限、原子不可分附加界限和实际是否满足会分别记录，违反时该前缀直接失败，不进入汇总。分数表示启发式调查重要性，不表示攻击概率。

PS-RDP-CPF 在此基础上增加**预声明因果路径覆盖**。POI 清单可用 `certificate_paths` 把主链和独立分支分开；系统只为同一声明路径内的相邻 POI 构造严格时序桥，绝不因为候选图断开而事后自动切分分支。每个 POI 必须在 path cover 中恰好出现一次。同一路径内部断开仍返回 `candidate_disconnected` 并立即终止该前缀；多条路径各自完整时返回 `valid_forest`。这既支持真实攻击的分叉结构，也防止用“分支”标签掩盖搜索漏边。

完整账本默认写到普通实验 JSON 同目录下的 `<输出文件名>-ledger/`；POI 前缀实验写到 `scenario-NN/poi-prefix-k-ledger/`。验证任意账本：

```bash
python -m tc_pruning.cli verify-score-ledger \
  --ledger output/tc/poi-prefix-sweep/RUN_ID/scenario-12/poi-prefix-8-ledger
```

高异常边可直接查看 `high-anomaly-edges.json`，全部边在 `edge-scores.jsonl.gz`，完整节点/边身份在 `candidate-graph.jsonl.gz`，定义、配置和哈希在 `manifest.json`。高异常集合没有 Top-N 截断：默认取正分边 99% 分位阈值与绝对分数 0.8 中较严格者，并包含阈值并列边。v2 验证器会重算候选图摘要、排名、分位阈值、全部并列边、逐预算决策和保留理由，还会核验每条边的证据键集合、嵌套数值有限性、noisy-OR 的支持数/胜出 POI 以及配置预算与决策列的一一对应；写后验证失败会直接中止实验。完整账本和高异常索引均采用流式临时文件写入，避免为高分边额外保留一份内存副本。

在线/离线边界是强制执行的：所有主预算的评分和剪枝决定先全部冻结，此后才允许解引用 Ground Truth 或查询真值事件。POI 前缀实验中的固定参考链通过惰性提供器在首轮在线剪枝结束后构建，后续仅复用缓存，因此真值查询不会预热在线阶段的 SQLite 页面缓存。

DEPIMPACT 特征按论文定义实现：`fS=1/(|se-sPOI|+α)`、`fT=ln(1+1/|te-tPOI|)`、`fC=OutDegree(DST)/InDegree(DST)`。相同 `⟨SRC,DST,REL⟩` 且相邻时间差不超过 10 秒的边先合并做特征学习，但保留原始 event ID 用于真值评估。数据量缺失时不会假装为 0，报告中的 `depimpact.data_size_coverage` 会给出有效覆盖率。

OOV 实体先查完整标签缓存；未见过的完整标签按词元组合，未进入历史词表的词元贡献零向量。文件实体使用路径共同前缀，网络实体使用 IP 共同二进制前缀，进程实体使用嵌入余弦相似度。

支持三种选择方式：

- `ratio`：按指定保留比例取 Top-K；
- `adaptive`：在排序分数的最大显著间隙处自动确定阈值，同时保证不少于 `keep_ratio` 指定的最低预算；没有有效间隙时使用该比例。
- `rdp_guard`：先硬保护所有 POI 及相邻有序阶段的最低代价时间因果桥，再按“组分数/原始事件成本”选择；装不下的大组会被跳过，并继续用较小组填充真实事件预算。

若路径证书本身超过预算，系统优先保链并通过 `budget_feasible=false`、`budget_overflow_edges` 明确报告；否则绝不超过按原始事件数计算的预算。默认配置保留映射成功的告警事件，保证“告警后重建”不会把触发器自身剪掉；若要研究告警筛除，应复制配置档并把 `pruning.protect_alert_edges` 设为 `false`。

## 已实现的可靠性修正

- 相同 Event UUID 对应不同事件时，不再因唯一约束静默丢边；数据库保留原始 ID，并为冲突记录生成稳定 ID。
- 频率模型只统计最早告警之前的历史，避免使用未来信息。
- KAIROS 边先按窗口去重，再使用时间、关系和端点语义严格映射。
- 仅对读类信息流事件允许端点反向匹配，写类事件不会错误反转。
- KAIROS 的五个告警窗口作为独立种子组扩展，避免无关窗口相互串联。
- 多告警使用边去重工作队列分别扩展，不设置单告警路径预算；解释路径不参与候选图构建。
- 可达性评估遵循事件方向和时间顺序，不再使用无向连通性夸大结果。
- 可选 `attack_paths` 支持严格的完整攻击路径覆盖率和保留率。
- NODOZE 路径正常度使用几何均值做长度归一化，校正原实现把固定衰减因子按每条边重复相乘的问题。
- 具体语义事件未见时回退到节点类型—关系频率，并对零概率和零稳定度做数值平滑，避免所有路径异常分饱和为 1。
- KAIROS 告警锚点不重复参与上下文异常评分，评分聚焦告警的前因和后果。
- 前向与后向路径合并时拒绝重复事件、重复节点和不连续链。

## 快速使用

安装：

```powershell
python -m pip install -r requirements.txt
```

导入 CDM18/CDM20 数据：

```powershell
python -m tc_pruning.cli ingest `
  --input data\ta1-cadets-e3-official-*.json `
  --db output\tc\cadets-e3-v2.db `
  --batch-size 50000
```

### DEPIMPACT crackhost2 官方示例

`DEPIMPACT/crackhost2.log` 是 sysdig 文本日志，不是 DARPA CDM JSON，因此不能交给原来的 `ingest`。新增的 `ingest-sysdig` 会流式配对系统调用的进入/退出记录，生成进程、文件、Socket 及信息流边；同时读取 `.property_demo`，把 `POI` 文件对应的最后一次同尺寸成功写入转换为现有 `--poi-events` 所需的事件 ID。原 CDM 接口保持不变。

从 `NODOZE-pruning-release` 目录执行：

```powershell
python -m tc_pruning.cli ingest-sysdig `
  --input ..\DEPIMPACT\crackhost2.log `
  --db output\depimpact\crackhost2.db `
  --poi-property ..\DEPIMPACT\crackhost2-backward.property_demo `
  --poi-output poi\crackhost2-poi.json `
  --host crackhost2 `
  --batch-size 50000

python -m tc_pruning.cli build-frequency-cache `
  --db output\depimpact\crackhost2.db

python -m tc_pruning.cli experiment `
  --db output\depimpact\crackhost2.db `
  --poi-events poi\crackhost2-poi.json `
  --output output\depimpact\crackhost2-pruning-results.json `
  --config configs\tc_pruning_depimpact_poi.json
```

该示例没有官方攻击真值，因此结果只能评价候选图规模、压缩率、POI 因果路径和不同预算下的结构保留情况，不能报告攻击节点召回率、精确率或 F1。

准备一个不依赖 KAIROS 的 POI 文件。简单数组中的多个 POI 默认属于同一个攻击事件；推荐的结构化格式还会保留攻击阶段顺序和显式调查窗口：

```json
{
  "event_ids": ["stage-1", "stage-2"],
  "seed_event_groups": [{
    "group_id": "incident-1",
    "seed_event_ids": ["stage-1", "stage-2"],
    "window_start_ns": 1523555940000000000,
    "window_end_ns": 1523558340000000000
  }]
}
```

直接运行自适应剪枝：

```powershell
python -m tc_pruning.cli experiment `
  --db output\tc\cadets-e3-v2.db `
  --poi-events poi-events.json `
  --groundtruth-annotations output\tc\ubc-cadets-e3\cadets-e3-ubc-06-annotations.json `
  --output output\tc\cadets-e3-poi-results.json `
  --config configs\tc_pruning.json
```

旧的 KAIROS 映射方式仍可用于复现实验：

```powershell
python -m tc_pruning.cli prepare-kairos-alerts `
  --db output\tc\cadets-e3-v2.db `
  --input kairos-cadets-e3-alerts.json `
  --output annotations\cadets-e3-kairos-alerts.json
```

使用旧清单运行：

```powershell
python -m tc_pruning.cli experiment `
  --db output\tc\cadets-e3-v2.db `
  --annotations annotations\cadets-e3-kairos-alerts.json `
  --output output\tc\cadets-e3-kairos-results.json `
  --config configs\tc_pruning.json
```

是否保护告警事件由配置中的 `pruning.protect_alert_edges` 决定。若设为 `false`，该实验必须标为“告警筛选消融”，不能与告警后重建主实验混报。大量告警事件会构成保留规模下限，因此压缩率必须使用报告中的 `actual_keep_ratio` 计算。

`--poi-events` 与 `--annotations` 必须二选一。更完整的 KAIROS 兼容说明见 `docs/kairos-cadets-e3-to-nodoze.md`。

### KAIROS 告警顺序前向累计模式

`configs/tc_pruning_kairos_forward.json` 默认启用
`causal_search.seed_strategy = window_context`。程序根据 KAIROS 提供的告警窗口，使用时间索引和键集分页读取窗口并集内的全部原始事件；重叠窗口按事件 ID 去重，不再对664条映射事件逐条执行完整搜索。664条是 KAIROS 告警摘要图中成功映射到 CADETS 数据库的事件，不是窗口内全部事件。

可将策略改成 `window_context_expand`，在窗口图基础上执行有界多源补全。补全共享优先队列、候选集合和方向相关的有效时间状态，并使用有容量上限的固定时间块邻居缓存。`expansion_direction` 支持 `forward`、`backward` 和 `both`。资源限制由 `resource_max_edges`、`resource_max_states`、`resource_timeout_seconds`、`resource_memory_mb` 和 `cache_max_blocks` 控制。

报告中的 `candidate_construction` 给出分页数、查询事件数、唯一候选数、数据库耗时、基线/峰值 RSS、状态复用和资源截断信息。该模式强制在最终累计图上统一剪枝，告警事件默认不全部硬保护。原来的 `configs/tc_pruning.json` 默认使用 `poi_bidirectional`，POI 双向搜索流程保持不变。

```powershell
python -m tc_pruning.cli experiment `
  --db output\tc\cadets-e3-v2.db `
  --annotations ..\annotations\cadets-e3-kairos-alerts.json `
  --groundtruth-annotations output\tc\ubc-cadets-e3\cadets-e3-ubc-06-annotations.json `
  --config configs\tc_pruning_kairos_forward.json `
  --output output\tc\kairos-forward-cumulative.json
```

## 标注格式与指标

当前可疑度引导的因果搜索要求输入至少包含 event ID；只有 `seed_uuids` 无法确定依赖方向和事件时间，因此会被明确拒绝。`--poi-events` 中未显式分组的多个事件默认合并为一个事件组；若有路径级真值，可增加：

```json
{
  "name": "cadets-case",
  "seed_event_ids": ["alert-event"],
  "attack_event_ids": ["e1", "e2", "e3"],
  "attack_node_uuids": ["n1", "n2", "n3", "n4"],
  "attack_paths": [["e1", "e2", "e3"]]
}
```

报告区分以下指标：

- `edge_compression`、`node_compression`：图规模压缩率；
- `attack_*_coverage`：真值中有多少进入候选图；
- `attack_*_retention`：候选图中已匹配真值有多少在剪枝后保留；
- `attack_reachability`：按有向时序因果关系仍可达的攻击节点比例；
- `attack_path_coverage`：完整路径全部出现在候选图中的比例；
- `attack_path_retention`：已匹配完整路径在剪枝后仍完整的比例。

如果没有 `attack_paths`，路径级两个指标返回 `null`，不能用事件边保留率代替。

## 正式实验建议

KAIROS 告警实验回答“外部检测器给出告警后，剪枝是否能保留相关上下文”；UBC/Orthrus 或人工标注实验回答“攻击真值是否被覆盖并完整保留”。论文中应分别报告两类实验，至少包括：

1. 稀有度单独、扩散单独、二者融合以及加入 NODOZE 路径分数的消融；
2. 固定比例与自适应阈值的对比；
3. 边/节点压缩率、攻击覆盖率、攻击保留率、完整路径保留率和运行时间；
4. 映射失败原因、配置文件、数据版本和告警前历史统计范围。

## 测试

```powershell
python -m pytest -q
```

## UBC06、UBC12、UBC13 分场景实验

第一次运行实验前必须先离线构建 Event Frequency Database：

```powershell
python -m tc_pruning.cli build-frequency-cache `
  --db output\tc\cadets-e3-v2.db
```

然后从按日聚合库编译三套可直接加载的最终模型快照：

```powershell
python -m tc_pruning.cli compile-ubc-frequency-snapshots `
  --db output\tc\cadets-e3-v2.db
```

输出位于 `output\tc\frequency-models\before-day-*.pkl.gz`。`experiment` 根据最早 POI 所在日期自动选择对应快照；所有 POI、压缩点和消融共享同一个内存模型。找不到匹配快照时会明确报错，不会退回在线扫描频率表。

这一步会扫描原始 `edges`，因此仍然较慢，但每个数据库只需执行一次。之后 `experiment` 只查询 `freq_event_daily`、`freq_src_rel_daily`、`freq_pattern_daily` 等按日聚合表；截止时间采用“只使用 POI 当天之前的完整日期”，避免把 POI 之后的同日事件泄漏进历史频率。如果数据库继续导入了新事件，缓存会被标记为失效，必须重新执行上述命令。

检查在线查询是否使用聚合表：

```powershell
python -m tc_pruning.cli explain-frequency-cache `
  --db output\tc\cadets-e3-v2.db
```

POI 搜索按组独立执行，但共享同一个方向邻接缓存；对相同节点和方向只做一次索引查询，之后按事件时间在内存中过滤。数据库已经包含 `(src,timestamp_ns)` 与 `(dst,timestamp_ns)` 两个复合索引。

先一次性生成三个相互独立的真值清单。每一天只从当天的 UBC 核心攻击事件中选择最多三个下游 POI，不会跨天混合：

```powershell
python -m tc_pruning.cli prepare-ubc-annotations `
  --db output\tc\cadets-e3-v2.db `
  --groundtruth-dir ubc-provenance-ground-truth-ff65bc7\darpa\E3-CADETS `
  --output-dir output\tc\ubc-cadets-e3 `
  --scenario all
```

对某一天运行时，同一个清单既提供该场景的 oracle POI，也提供独立评价所需的 edge/path 真值。例如 UBC12：

```powershell
python -m tc_pruning.cli experiment `
  --db output\tc\cadets-e3-v2.db `
  --annotations output\tc\ubc-cadets-e3\cadets-e3-ubc-12-annotations.json `
  --groundtruth-annotations output\tc\ubc-cadets-e3\cadets-e3-ubc-12-annotations.json `
  --output output\tc\ubc-cadets-e3\cadets-e3-ubc-12-connectivity-results.json `
  --config configs\tc_pruning.json
```

把命令中的 `12` 分别替换成 `06`、`13` 即可运行另外两个场景。该方式使用真值派生 POI，只评价“给定正确 POI 后的搜索和剪枝上界”，不能当作独立检测结果。

若 POI 来自 DARPA 报告中的攻击阶段，可用 `--poi-events` 覆盖自动选择。下例会把有序 POI 写入一个带官方时间窗的单事件组，并让生成的真值路径终止于这些 POI：

```bash
python -m tc_pruning.cli prepare-ubc-annotations \
  --db output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db \
  --groundtruth-dir darpa/E3-CADETS \
  --output-dir output/tc/ubc-cadets-e3/pdf-stage \
  --scenario 12 \
  --poi-events poi/cadets-e3-ubc-12-pdf-stage-pois.json

python -m tc_pruning.cli experiment \
  --db output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db \
  --annotations output/tc/ubc-cadets-e3/pdf-stage/cadets-e3-ubc-12-annotations.json \
  --groundtruth-annotations output/tc/ubc-cadets-e3/pdf-stage/cadets-e3-ubc-12-annotations.json \
  --config configs/tc_pruning_poi_alert.json \
  --output output/tc/ubc-cadets-e3/pdf-stage/cadets-e3-ubc-12-poi-alert-results.json
```

Linux 后台运行并按日期时间命名日志和结果：

```bash
run_stamp="$(date +%Y-%m-%d_%H-%M-%S)"
result_path="output/tc/ubc-cadets-e3/pdf-stage/cadets-e3-ubc-12-rdp-guard-${run_stamp}.json"
log_path="logs/cadets-e3-ubc-12-rdp-guard-${run_stamp}.log"
nohup python -m tc_pruning.cli experiment \
  --db output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db \
  --annotations output/tc/ubc-cadets-e3/pdf-stage/cadets-e3-ubc-12-annotations.json \
  --groundtruth-annotations output/tc/ubc-cadets-e3/pdf-stage/cadets-e3-ubc-12-annotations.json \
  --config configs/tc_pruning_poi_alert.json \
  --output "$result_path" > "$log_path" 2>&1 &
run_pid=$!
printf 'PID=%s\nLOG=%s\nRESULT=%s\n' "$run_pid" "$log_path" "$result_path"
```

查看进度：

```bash
ps -p "$run_pid" -o pid,etime,%cpu,%mem,rss,cmd
tail -f "$log_path"
cat "${result_path}.progress.json"
```

`tc_pruning_poi_alert.json` 在完整场景窗口内启用 `fusion_mode=rdp_guard`、`diffusion_mode=time_respecting_bidir`、`pruning.mode=rdp_guard` 和 `certificate_topology_policy=causal_path_cover`。每条预声明路径内部相邻 POI 的时序因果骨架是硬约束，分支之间不虚构因果边；当骨架本身超过请求预算时，报告通过 `budget_feasible=false` 和 `budget_overflow_edges` 显式说明，不会静默剪断攻击链。

输出的论文主表位于 `paper_main_results.rows`，每个压缩点只保留以下列：场景、方法、节点前/后、事件前/后、事件压缩率、攻击事件召回率、完整路径保留率和单次端到端耗时。`complete_path_retention` 采用严格定义：一条预先标注的 Ground Truth 路径中所有事件 ID 都仍在输出图中，才算该路径被完整保留；没有提供显式路径时返回 `null`，不使用普通可达率代替。事件均按场景级去重 event ID 计算，不累加多 POI 重复归属。

### 基于攻击描述的 DEPIMPACT 风格 POI

不使用 KAIROS 时，`poi/cadets-e3-ubc-{06,12,13}-description-pois.json` 给出根据 DARPA 攻击描述在事件数据库中核验的具体 POI。它们是 `report_derived_oracle_proxy`：用于评价“给定报告级告警后的剪枝能力”，不能冒充检测器端到端结果。每个 POI 独立评分，最终在同一候选图和全局原始事件预算下剪枝；Ground Truth 文件仅在搜索、评分、证书和剪枝冻结后参与评价。

UBC-13 使用窗口内首次 nginx→`155.162.39.48:80` 与首次 pEja72mA→`53.158.101.118:80` 作为主链阶段，严格证书能复核 nginx→`/tmp/pEja72mA`→execute→pEja 的桥。DARPA 报告明确记载 sshd 注入多次失败，因此 sshd→`198.115.236.119:80` 在 POI 清单中预先声明为独立分支，不再错误串接到 pEja C2 后面。

POI 搜索严格遵守配置项 `expansion_direction`。对 CDM 中归一化为“对象 → 主体”的读取类事件，后向搜索从主体节点开始；POI 边本身从扩展阶段排除，防止同一告警事件在重建路径中重复出现。

CADET-E3 描述驱动实验在候选搜索阶段仍逐 POI 隔离，但在剪枝阶段对合并候选图使用单一全局预算。这样保留率对应最终交付图的真实规模，不会因多个 POI 分别占满预算后再取并集而膨胀。

在已经激活 `graphenv` 的 PowerShell 中连续运行三个场景：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_ubc_description_pois.ps1
```

该脚本默认先从
`ubc-provenance-ground-truth-ff65bc7/darpa/E3-CADETS/node_Nginx_Backdoor_{06,12,13}.csv`
重新生成独立评价真值到
`output/tc/ubc-cadets-e3/ubc-provenance-source/`，并在每个 JSON 中记录原始
CSV 的 SHA-256。CSV 提供人工审查的攻击实体 UUID；攻击事件集合定义为场景时间窗内、
两端均属于这些实体的数据库事件。描述驱动 POI 文件独立提供给在线搜索，不从评价真值生成。

该脚本依次写出 `output/tc/ubc-cadets-e3/cadets-e3-ubc-{06,12,13}-e3-report-poi-results.json`，任一场景失败时立即停止，不会把失败后的部分结果当作完整实验。

脚本完成三个实验后还会按 `docs/EVALUATION_PROTOCOL_V2.md` 生成审计版结果，写入
`output/tc/ubc-cadets-e3/protocol-v2/`。如果只需重新统计已有结果而不运行搜索：

```powershell
python scripts\generate_protocol_v2_reports.py
```

单个历史结果也可以使用：

```powershell
python -m tc_pruning.cli report-protocol-v2 `
  --db output\tc\cadets-e3-v2.db `
  --result output\tc\ubc-cadets-e3\cadets-e3-ubc-06-e3-report-poi-results.json `
  --annotations output\tc\ubc-cadets-e3\ubc-provenance-source\cadets-e3-ubc-06-annotations.json `
  --output output\tc\ubc-cadets-e3\protocol-v2\cadets-e3-ubc-06-protocol-v2.json
```

`labeled_attack_event_fraction_in_output` 不能无条件解释为完备真值下的误报精确率：UBC 等真值可能只标注核心攻击事件，输出集合中未标注的事件属于“标签未知”，不能直接认定为正常或误报。`critical_causal_relation_recovery` 同时报告时间合法有向可达率、真值连接证据保留率，并取二者较低值作为严格联合恢复率，避免用无关替代路径获得完整恢复分数。峰值内存采用进程 RSS 每 10 ms 采样，包含 Python、原生扩展和 SQLite 在本进程中的驻留内存；极短暂且小于采样间隔的尖峰仍可能被遗漏。
最终剪枝先选择稀有度与扩散得到的可疑核心，再用边代价 `1-final_score` 补回核心到 POI 的最低代价、时间一致有向因果桥。

候选覆盖异常时，使用独立诊断命令关闭可疑度、分位数和 frontier 提前停止，仅保留信息流方向、时间单调性和防循环状态。诊断有全任务 120 秒、100 万边和 25 万状态安全保护，任何触发都会输出 `resource_protection.incomplete=true`：

```powershell
python -m tc_pruning.cli diagnose-search `
  --db output\tc\cadets-e3-v2.db `
  --annotations output\tc\ubc-cadets-e3\cadets-e3-ubc-12-annotations.json `
  --groundtruth-annotations output\tc\ubc-cadets-e3\cadets-e3-ubc-12-annotations.json `
  --current-results output\tc\ubc-cadets-e3\cadets-e3-ubc-12-new-metrics-only.json `
  --config configs\tc_pruning.json `
  --output output\tc\ubc-cadets-e3\cadets-e3-ubc-12-search-diagnostic.json
```

`coverage_funnel_before_pruning` 依次报告真值清单、数据库匹配、POI 时间因果范围、无启发式诊断搜索和当前候选搜索的唯一事件数量；`key_relation_recovery_before_pruning` 分别报告因果范围、诊断候选和当前候选的时间合法可达率及真值连接证据保留率。Ground Truth 只参与离线计数和独立范围核验，不指导搜索。

UBC 的 edge/path 真值由“人工复核核心节点 + 官方场景时间窗”派生，并不是 UBC 官方逐边人工标注。清单中的 `metadata.path_quality` 会明确记录这一限制。若 `depimpact.data_size_coverage=0`，报告会标记为 `adapted_DEPIMPACT_without_data_flow_amount`。

## DEPIMPACT 多 POI 与无路径上限搜索（新版）

新版候选图构建遵循 DEPIMPACT 的因果工作队列思路，但采用 rarity/temporal/fanout 最大优先队列和自适应局部时间窗。每个 POI 独立搜索并共享方向邻居缓存；高相关边界触发扩窗，frontier 最大相关度低于阈值时自然停止。候选图不设置正常情况下的最大路径数或最大跳数；资源上限仅是可选安全熔断，一旦触发，报告会明确标记结果不完整。

搜索状态由 `方向 + 实体 + 有效事件时间` 标识，而不是只用实体 UUID 标记 visited。因此网络收发等合法的 `socket → process → socket → process` 时间序列可以再次经过同一实体。局部异常分位只用于优先队列调度，不再在候选构建前硬删除时间有效事件；POI 同时间、同 `SRC/DST/REL` 的并行事件也作为同一依赖证据保留。

剪枝预算统一按去重后的原始事件数计算。10 秒边合并只提供表示组及其原始事件映射；选择一个组、保护 POI 或补充连接路径时，其全部原始事件成本都会在选择阶段计入。组按“得分/原始事件成本”形成嵌套前缀，连接路径不再事后无上限补边。结果中的 `budget_edges`、`minimum_required_edges`、`budget_feasible` 和 `budget_overflow_edges` 用于区分普通预算、不可行的最低证据成本以及实际超额；`actual_keep_ratio` 仍以原始候选事件为分母。

当提供 Ground Truth 时，报告额外输出 `candidate_miss_diagnostics`、`groundtruth_assignment_diagnostics` 和 `time_respecting_groundtruth_evaluation`。这些字段仅用于离线诊断，不参与在线搜索、评分或剪枝；原有的宽松连通分量口径保持不变，时间有效口径作为补充结果单独报告。

报告中的 `candidate_path_count` 现在只是从完整候选图投影出的解释路径数量，不参与候选边选择。判断搜索是否完整，应检查：

```json
"candidate_graph_has_path_limit": false,
"search_diagnostics": {
  "truncated_path_count": 0
}
```

DEPIMPACT 评分现在包括论文公式（7）的反向影响传播。POI 两端初始影响为 1，其他节点反复取其后继节点影响的归一化加权和，直到总变化量小于 `1e-13`。报告中的 `depimpact.propagation_converged`、`propagation_iterations` 和 `convergence_delta` 用于检查收敛。

可从检测器候选事件中自动选择多个下游 POI：

```powershell
python -m tc_pruning.cli select-pois `
  --db output\tc\cadets-e3-v2.db `
  --candidates detector-events.json `
  --output poi-events.json `
  --max-pois 5 `
  --source-kind detector
```

选择器综合事件稀有度、是否位于因果末端、目的节点汇聚性、数据流规模、时间位置和关系类型，并优先保证不同 POI 指向不同目的实体。`--max-pois` 是最多选择多少个 POI，不是必须凑满；没有足够高质量的末端事件时会返回更少。

仅评估剪枝上界时，可以从 UBC06 官方核心攻击事件选择 oracle POI：

```powershell
python -m tc_pruning.cli select-pois `
  --db output\tc\cadets-e3-v2.db `
  --candidates output\tc\ubc-cadets-e3\cadets-e3-ubc-06-annotations.json `
  --output poi-events-ubc06.json `
  --max-pois 2 `
  --source-kind groundtruth
```

此输出会写入 `oracle_derived: true`。它可以评价“给定正确症状后，搜索和剪枝能否恢复攻击上下文”，但不能评价检测器能否发现攻击。运行剪枝：

```powershell
python -m tc_pruning.cli experiment `
  --db output\tc\cadets-e3-v2.db `
  --poi-events poi-events-ubc06.json `
  --groundtruth-annotations output\tc\ubc-cadets-e3\cadets-e3-ubc-06-annotations.json `
  --output output\tc\cadets-e3-depimpact-multipoi-results.json `
  --config configs\tc_pruning.json
```

测试覆盖 CDM 解析、SQLite 导入、频率统计、NODOZE 因果搜索、KAIROS 映射、扩散、剪枝、路径指标和 CLI 端到端流程。

## 按告警对齐独立攻击真值

正式重建实验必须把检测输入和评估真值分开。`--annotations` 只提供外部检测器告警，`--groundtruth-annotations` 只提供攻击真值：

```powershell
python -m tc_pruning.cli experiment `
  --db output\tc\cadets-e3-v2.db `
  --annotations annotations\cadets-e3-kairos-alerts.json `
  --groundtruth-annotations output\tc\ubc-cadets-e3\cadets-e3-ubc-06-annotations.json `
  --output output\tc\kairos-ubc06-alert-aligned.json `
  --config configs\tc_pruning.json
```

`alert_aligned_evaluation` 以单个告警窗口为评估单位。只有告警事件与真值事件直接重合的 `strong` 关联进入主指标；仅节点重合记为 `weak`，无重合记为 `none`，二者只作诊断。报告区分：

- `candidate_attack_*_recall`：告警因果搜索是否找到对应攻击子图；
- `conditional_attack_*_retention`：已经进入候选图的攻击内容是否被剪枝误删；
- `candidate_context_edge_recall`、`pruned_context_edge_recall`、`conditional_context_edge_retention`：剔除输入告警事件自身后，真正重建出的攻击上下文；
- `pruned_context_edge_precision`、`pruned_context_edge_f1`：非锚点上下文的纯度与综合质量；
- `pruned_attack_*_recall`：从真实告警相关攻击子图到最终剪枝图的端到端召回率；
- `pruned_*_precision` 和 `pruned_*_f1`：最终图中真实攻击内容的纯度与综合质量；
- `control_dependency`、`data_dependency`：NODOZE 风格的控制依赖与数据依赖 TP、FP、召回率和假阳性率。

原有 `attack_*_coverage` 仍保留为场景级诊断指标，但不能再单独用于评价局部告警剪枝。请求比例不等于实际比例，论文只能用 `actual_keep_ratio` 及 `1 - actual_keep_ratio` 报告压缩率。UBC 12/13 当前使用真值派生种子，只能报告为 oracle-seed 上界；KAIROS 与 UBC 06 的双输入实验才是当前独立告警条件下的端到端评估。

当前 UBC06 清单没有逐告警 `attack_paths`，因此报告会把 `groundtruth_scope_quality` 标为 `event_connected_component_proxy`：它是由真值事件构成的相关连通分量，而不是人工核验的逐告警精确依赖图。该结果可用于当前实验和系统消融，但若要支撑顶会级“完整攻击链保持”结论，还必须补充逐告警精确路径标注，并报告严格的整路径召回率。
# 三日 POI 前缀增量实验

CADETS E3 的 UBC-06、UBC-12、UBC-13 可以按 DARPA 报告时间线从一个 POI 开始逐个增加，在固定 20% 原始事件预算下测量完整路径和“尚未作为种子的终端路径”恢复率：

```bash
python -m tc_pruning.cli poi-prefix-experiment \
  --db output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db \
  --spec configs/cadets_e3_poi_prefix_sweep.json \
  --config configs/tc_pruning_poi_alert.json \
  --output-dir output/tc/poi-prefix-sweep/manual-run
```

后台执行并用启动日期时间同时命名结果目录和日志：

```bash
cd /root/NODOZE-pruning-release
run_id=$(date '+%Y-%m-%d_%H-%M-%S')
log_file="$PWD/logs/ps-rdp-cadets-poi-prefix-${run_id}.log"
setsid -f bash scripts/run_cadets_poi_prefix_sweep.sh "$run_id" \
  > "$log_file" 2>&1 < /dev/null
printf 'RUN_ID=%s\nLOG=%s\n' "$run_id" "$log_file"
```

运行中查看当前攻击日、POI 数和内部阶段：

```bash
tail -f logs/ps-rdp-cadets-poi-prefix-YYYY-MM-DD_HH-MM-SS.log
cat output/tc/poi-prefix-sweep/YYYY-MM-DD_HH-MM-SS/progress.json
cat output/tc/poi-prefix-sweep/YYYY-MM-DD_HH-MM-SS/process-status.json
```

启动脚本会在 14 个前缀完成后自动调用独立 v3 sweep 验证器；只有候选图/账本哈希、逐边决策、path-cover 拓扑、严格 witness、预算、前缀单调性和 churn 全部可复算时，`process-status.json` 才会同时写入 `status=complete` 与 `validation_status=passed`。也可手工复核：

```bash
python scripts/validate_ps_rdp_sweep.py \
  output/tc/poi-prefix-sweep/YYYY-MM-DD_HH-MM-SS
```

完成后主要读取 `summary.md` 或 `summary.json`。同时会生成
`table7-runtime.{csv,md}` 和 `table8-entry-ranks.{csv,md}`：前者按照
DEPIMPACT 表 7 的口径拆分因果图构建、边合并、依赖权重计算、反向传播和
NoDoze 时间；后者按照表 8 的口径，在 network/file/process 三类候选入口中
报告真实攻击入口的平均排名，并比较 temporal-only、temporal+data、固定投影、
固定种子随机基线和学习投影。每个结果 JSON 的
`depimpact_table8_entry_ranks` 还保存完整候选入口分数、并列中位排名、真值覆盖率
和随机种子，真值只在在线剪枝完成后使用。

v3 中 `minimum_sufficient_poi_count` 明确表示“最早合法且恢复全部固定参考路径”的
POI 数；这些路径是 POI 锚定的参考路径，不等于独立攻击数量。若无解则为
`null`。`earliest_legal_poi_count_at_max_path_retention` 另报合法点中的最佳平台，
`minimum_observed_poi_count_for_full_path_retention` 则保留不考虑证书是否合法的
观察值，防止把失败证书误称为 sufficient。`unselected_terminal_path_retention`
排除了已选作 POI 的终端路径，用来避免硬保护种子造成的指标虚高。

## RASP-D 实验更新

新增保持评分不变的多样性/边际收益递减选边分支，提供四案例、四预算和权重消融，以及逐事件决策账本。20% 预算有提升，低预算存在明显退步，网页默认仍保留 RASP。论文依据、完整结果和后台复现命令见 [RASP-D 实验说明](docs/rasp-diverse.md)。
