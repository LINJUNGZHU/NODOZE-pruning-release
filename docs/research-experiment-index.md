# 五案例频率扩散实验索引

完整叙述见[算法、实验流程、借鉴方法与结果总说明](experiment-methods-overview.md)，含公式、伪代码、跨领域来源、对比结果及复现命令。

所有轮次保留各自的冻结配置、决策、对照和失败结果。五案例是开发集；
本地部分正例的 proxy 指标不等同于 SPARSE 官方逐事件指标。第五案例
使用 TRACE 工件推断映射，尚未证实就是论文 THEIA Case 5。

| 阶段 | 报告 | 内容 |
|---|---|---|
| 参考标注 | [本地关键事件](sparse-five-local-critical-study.md) | POI、参考事件和标注边界 |
| 频率扩散 | [实验报告](frequency-diffusion-study.md) | 频率、背景对比扩散及原始预算 |
| 跨领域对照 | [实验报告](cross-domain-study.md) | PCST、图稀疏化、覆盖选择 |
| 时间与路径 | [v1–v4](temporal-diffusion-study.md) | 时间条件、PPR/热核、配额与原始路径 |
| 边际收益 | [v5](marginal-witness-study.md) | 同池贪心/MILP、同选择规则的PPR/热核 |
| 历史与通道 | [v6](history-channel-study.md) | 历史条件频率、通道共享和候选扩展 |

v6 主要入口：

- `scripts/prepare_conditional_history.py`：只读历史统计与缓存。
- `scripts/run_history_channel.py`：选边实验，不读取参考标签。
- `scripts/evaluate_marginal_witness.py`：冻结输出后的独立评估。
- `scripts/profile_history_channel.py`：独立进程时间与内存测量。

绝对事件预算为64/256/1024/4096，主预算1024。各方法需同时看事件
召回、关键组/阶段覆盖、实际原始边数、时间路径可达率和成本。
已有网页/CLI默认算法未被这些开发实验自动替换。
