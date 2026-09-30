# 研究入口

当前工作线是 **chain-workbench-v2**。这里集中列出实验、历史结果和本机数据入口；最新运行 `20260930-r1` 已完成9个E3案例、36个变体和2520个决策点，参数与结论以[聚合报告](../docs/chain-workbench-v2/report.json)为准。

| 入口 | 用途 |
|---|---|
| [v2 方法与实验报告](../docs/chain-workbench-v2/README.md) | 当前工作线：候选窗口、多调查起点、上下文稀有度与保留图 |
| [参考子图完整性](../docs/reference-subgraphs/README.md) | 在同一冻结选择上检查分叉、汇合、全部必需事件及固定入口—出口可达性 |
| [按保留目标调整压缩率](../docs/retention-targets/README.md) | 设定事件／依赖保留目标，从已测预算中选最高达标压缩率；明确标记参考驱动的离线筛选 |
| [v2 研究工作台页面](../webapp/frontend/research-workbench.html) | 切换案例、候选范围、POI策略与预算，查看聚合曲线及阶段损失 |
| [v2 固定配置](../configs/chain_workbench_v2.json) | 案例数据入口、方法参数、预算与数据就绪登记 |
| [实际保留链路页面](../webapp/frontend/retained-chains.html) | 查看全部保留事件、严格时间路径、单事件和已观测调查见证 |
| [v1 冻结结果](../docs/adaptive-chain-results.md) | 已归档工作线：压缩率—参考链完整保留率及其限制 |
| [v1 曲线页面](../webapp/frontend/chain-study.html) | 查看冻结的参考链实验汇总 |
| [既有实验索引](../docs/research-experiment-index.md) | 五案例、频率扩散、时序路径、v8 事件组等既有研究 |
| [实验登记表](experiments.json) | 可供程序读取的当前/归档工作线、路径和数据可用性 |

启动项目网页后，研究工作台入口为 `/assets/research-workbench.html`，实际保留链路入口为 `/assets/retained-chains.html`。真实事件明细来自本机目录；公开仓库只登记入口与聚合说明。保留图的路径数不等于攻击链数量，自动构造的参考链也不自动成为完整攻击真值。

## 从冻结结果到页面

运行、离线评估、图表和实际保留图导出分别使用以下入口；完整命令和HTML目录示例见 [v2 说明](../docs/chain-workbench-v2/README.md#文件组织与复现)。

| 操作 | 入口与产物 |
|---|---|
| 固定参数执行单个登记案例 | `python -m scripts.run_chain_workbench`；输出 `registration.json`、`case.json`、各变体冻结文件 |
| 先验证全体冻结工件，再打开离线参考 | `python -m scripts.evaluate_chain_workbench`；生成聚合 `report.json` 与同名CSV |
| 导出论文图表 | `python -m scripts.plot_chain_workbench`；当前候选/固定候选范围的参考链曲线、等预算增量正例对照，各含PDF、PNG、SVG |
| 导出某一实际选择 | `python -m scripts.export_chain_workbench`；按方法和整数事件预算读取冻结掩码，输出JSON、CSV、GraphML |
| 本机逐条审查固定参考 | `python -m scripts.export_chain_reference_audit`；在验证后生成离线参考路径、断点与成员事件叠加文件，不修改选择 |
| 参考子图事后结构分析 | `python -m scripts.evaluate_reference_subgraphs`；校验同一批冻结选择，区分严格完整性、端点可达性和阶段损失；`scripts.plot_reference_subgraphs` 生成对应曲线 |
| HTML聚合入口 | `webapp/frontend/chain-workbench-summary.json`；来自聚合报告，不包含逐事件数据 |
| HTML详细导出入口 | `webapp/frontend/retained-chain-catalog.json`；本机目录条目指向实际导出文件 |

每个运行使用新的目录。登记案例目录已存在却没有`case.json`时，即使还没写出`registration.json`，也会阻止离线评估；默认还要求配置登记的所有案例都已完成。明确的已完成子集检查需使用 `--allow-partial`，报告会列出登记数、完成数与缺失案例，不能用作本轮完整9案例矩阵。完整参考链分母来自每案例固定的源正例子图见证，固定范围压缩率的分母来自本轮最大候选范围，两者都不是现实全部攻击的总量。

原始数据库、冻结候选、精确掩码和详细导出用于本机复核；聚合JSON、CSV和图表用于比较与公开展示。无参考标注或零分母显示N/A，不能用空集合得到100%保留率；E3已有开发案例也不能充当独立未见测试。

参考路径还应同时查看覆盖的不同正例数、单例数及合成`LINEAGE`依赖。当前TRACE工件的3条参考路径只覆盖31个正例中的4个，且全部依赖合成关系；即便路径保留达到100%，也不能称为31个正例或现实完整攻击全部保留。新增上下文历史严格早于完整候选窗口，但部分既有稀有度分数沿用首POI前的频次统计，两者时间范围不同，详见v2协议。

## 本机目录

运行整理脚本后，`research/local/` 提供三个相对链接：

| 链接 | 目标 |
|---|---|
| `local/datasets` | `output/tc/`，既有数据与候选工件 |
| `local/exports` | `webapp/frontend/retained-chain-data/`，JSON、CSV、GraphML |
| `local/current` | `output/research/chain-workbench-v2/`，当前实验输出 |

本机另外提供 `local/latest` 指向 `20260930-r1`，以及 `local/papers` 指向用户提供的论文目录。这两个本机快捷入口不随 Git 上传。

数据目录不搬迁、不复制；目标尚未生成时，链接可以暂时悬空。可选的 `local/data-inventory.json` 只在本机保存数据盘点。`research/local/` 与事件明细不提交到仓库。

E3 已有本地事件数据。当前盘点只在本机找到 E5 参考标注及报告，未找到可运行的 E5 原始事件或事件数据库；这不构成 E5 实验结果，也不能用 E3 的 case5 替代 E5。

## 整理已有输出

从项目根目录预览，默认不改动文件：

```bash
python -m scripts.organize_research_workspace --project-root .
```

确认冻结输入的使用进程已经结束后，显式执行：

```bash
python -m scripts.organize_research_workspace --project-root . --apply
```

如需保留已有本机盘点，可附加 `--inventory /tmp/nodoze-e3-e5-inventory.json`。脚本先检查全部目标；存在冲突则拒绝执行，不覆盖已有数据。它只整理下列两个已知实验目录：

| 旧路径 | 归档路径 |
|---|---|
| `output/adaptive-chain-study-20260929/` | `output/research/archive/chain-study-v1-exploratory/` |
| `output/adaptive-chain-study-20260929-final/` | `output/research/archive/chain-study-v1-final/` |

旧路径保留为相对兼容链接，冻结文件内容保持原样；重复执行不会再次搬迁。脚本不扫描或整理其他实验、源数据库、论文及用户目录。预检防止已存在的路径冲突；执行期间不要并发修改这些目录，移动过程不提供断电事务保证。
