# NODOZE pruning：A_rasp、A_rasp-PBR 与 C_branch_fair

本研究分支比较三种 provenance-graph 剪枝方法：`A_rasp`、`A_rasp-PBR` 和 `C_branch_fair`。其中 `A_rasp-PBR` 是当前效果最好的算法：它先生成较小的 A_rasp 基础图，再根据 detector-local POI 的严格时序可达需求，补回被预算门控遗漏的最小桥接事件。

当前正式评估覆盖两套数据：

- **CADETS E3**：使用既有检测器告警作为 POI，使用 ORTHRUS Ground Truth 做冻结后的离线评价。
- **TRACE E3**：先由 KAIROS 产生并冻结 POI，再使用 ORTHRUS Ground Truth 评价这些 POI 所属攻击范围内的节点、关键边和严格时序路径。

Ground Truth 不参与候选构建、评分或剪枝，只在在线结果冻结后参与评价。

## 当前最好结果

| 数据集 | 候选原始事件 | 方法 | 最终原始事件 | 攻击节点 | 关键边 | 严格路径 |
|---|---:|---|---:|---:|---:|---:|
| CADETS E3 | 50,000 | A_rasp-PBR | 845 | 49/50 | 31/32 | 38/39 |
| TRACE E3 | 20,000 | A_rasp-PBR | 11,232 | 19/19 | 11/11 | 9/9 |

CADETS E3 上，A_rasp-PBR 只保留候选事件的 **1.69%**，同时恢复 98.0% 的攻击节点、96.9% 的关键边和 97.4% 的严格路径。TRACE E3 上，它在 KAIROS 告警覆盖到的攻击范围内恢复全部 19 个攻击节点、11 条关键边和 9 条严格路径，并保留候选事件的 56.16%。两个比例不可直接横向排名，因为数据密度、告警覆盖和路径定义不同。

与基线相比：

- CADETS E3：A_rasp-PBR 的严格路径为 `38/39`，A_rasp 为 `31/39`，C_branch_fair 为 `33/39`。
- TRACE E3：A_rasp-PBR 的关键边/严格路径为 `11/11`、`9/9`；A_rasp 与 C_branch_fair 都为 `10/11`、`8/9`。
- A_rasp-PBR 不是新的检测器；它提升的是给定 POI 后的攻击上下文恢复能力。

完整口径、实验身份和限制见 [研究交接文档](docs/A_RASP_C_BRANCH_FAIR_HANDOFF.md)。

## 算法关系

```text
检测器告警 / POI
        │
        ▼
统一时序候选图
        │
        ├── A_rasp：稀有度 + restart propagation + 时序证据选择
        ├── C_branch_fair：分支相关性 + branch-fair lazy greedy
        └── A_rasp-PBR：较小 A_rasp 基础图
                         + detector-local demand pair
                         + 严格时序桥接修复
        │
        ▼
冻结剪枝结果 ──> ORTHRUS-only 离线评价
```

三个算法使用同一候选图和同一事件成本口径。PBR 的补边条件来自检测器 POI 与候选图可达性，不读取 Ground Truth。

## 主要入口

| 用途 | 文件 |
|---|---|
| A_rasp-PBR 核心算法 | `tc_pruning/pbr.py` |
| PBR 实验与指标 | `tc_pruning/pbr_experiment.py` |
| PBR 独立审计 | `tc_pruning/pbr_audit.py` |
| TRACE KAIROS POI 适配 | `tc_pruning/trace_kairos.py` |
| TRACE 实验驱动 | `tc_pruning/trace_kairos_experiment.py` |
| ORTHRUS Ground Truth 读取 | `tc_pruning/orthrus_groundtruth.py` |
| CADETS 配置 | `configs/a_rasp_pbr_cadets_e3.json` |
| TRACE 流水线 | `scripts/run_trace_e3_kairos_pipeline.sh` |
| 双数据集结果页面 | `webapp/frontend/index.html` |

## 运行与验证

运行 CADETS E3 PBR 实验：

```bash
bash scripts/launch_pbr_experiment.sh configs/a_rasp_pbr_cadets_e3.json
```

TRACE E3 完整流程入口：

```bash
bash scripts/launch_trace_e3_kairos_pipeline.sh
```

运行本研究分支的核心回归测试：

```bash
PYTHONPATH=. pytest -q \
  tests/test_pbr.py \
  tests/test_pbr_audit.py \
  tests/test_pbr_experiment.py \
  tests/test_trace_kairos.py \
  tests/test_trace_kairos_experiment.py \
  webapp/tests/test_pbr_html.py
```

网页以表格和图形同时展示两个数据集的攻击节点、关键边、严格路径和剪枝比例。原始数据库、模型产物、PDF 与实验输出不提交到 Git；仓库只保留实现、配置、可复核测试和汇总结论。
