# NODOZE 调查工作台

页面按三步使用：**选案例 → 看剪枝效果 → 核验可疑进程**。提供四个真实 OPTC 窗口，全量图最大 188,609 条边。详情分为攻击线索、事件日志与评分、运行记录；高级参数默认折叠。

默认使用增强规则（组合行为 + 受限进程创建链），旧规则保留对照。[增强规则实测与 TAPAS 标注核查](../docs/rule-lineage-method.md)。

另有真实训练的自监督图模型，可切换“深度学习 · 实验”后点击“重新分析”。当前实测未优于规则，因此神经模型保持实验选项。[方法、论文来源和完整负结果](../docs/deep-graph-method.md)。

## 当前服务器启动

已准备数据和模型时，在仓库根目录运行：

```bash
python webapp/backend/app.py
```

打开 `http://127.0.0.1:8000`；远程可使用 SSH 转发。`NODOZE_WEB_HOST`、`NODOZE_WEB_PORT` 调整监听配置。

## 四个真实案例

日期均为 2019-09-23，时间为 UTC−04:00，同一主机 SysClient0201。

| 案例 | 时间 | 原始事件 | 默认保留事件 |
|---|---|---:|---:|
| 入侵起点 | 11:20–11:30 | 27,011 | 5,402 |
| 扩大调查 | 11:20–11:50 | 86,318 | 17,263 |
| 大图对照 | 11:20–12:20 | 188,609 | 37,721 |
| 背景对照 | 10:50–11:10 | 74,654 | 14,034 |

所有 FILE/PROCESS/FLOW 原始事件按 ID 去重；三个攻击窗口重叠，不是三个独立攻击数据集。背景窗口没有公开标注攻击进程，也保留实际误报结果。

旧版仅画 80 条时间样本加 POI，新版 `/view` 接口和 Canvas 包含每条原始事件，无抽样。两张图坐标相同，滚轮/按钮缩放、拖动平移、点击节点搜索相关日志。重合的事件可能视觉覆盖；实际条数始终按原始事件计数，完整方向在活动路径和日志中核验。

## 页面操作

1. 点击案例卡。其事件数就是候选图原始规模。
2. 选择调查起点（POI）。三个攻击预设来自项目 Ground Truth：下载 runme.bat、初始 PowerShell C2、提权代理 C2。默认最后一项。背景案例的起点明确标为普通调查事件。
3. 选择“增强规则 · 进程链”、“旧规则 · 对照”或“深度学习 · 实验”、保留边上限，点击“重新分析”。结果保存到当前案例，其余案例不变；失败保留上次成功结果。
4. 查看“攻击线索”：点击进程看依据与支持日志，路径下的事件按钮打开真实记录。参考标签与算法预测分开，页面显示 Precision、Recall、F1、命中/误报/漏报，并单独显示 TAPAS 静态进程清单的召回与标签分歧。“查看活动事件”可检索预测进程生命周期内的全部候选活动，不仅是路径片段。
5. 在“事件日志与评分”中搜索文件、IP、进程、节点 UUID 或事件 ID。每页 20 条，评分曲线对应当前页真实分数；点击分数点或事件行可查看完整精度、判定原因、历史频率和原始日志。“将此事件设为调查起点”填写 POI，但需重新分析才生效。
6. “运行记录”提供历史计数、数据来源和剪枝审计下载；攻击页另有调查报告下载。

自定义事件 ID、剪枝范围、异常分位线在折叠的高级设置中，它只决定旧规则判定和增强规则的复核队列。神经模型阈值固定，不会随规则分位线变化。边评分用于调查排序，增强规则按组合证据和创建链判定，异常分仅用于排序/复核；各分数都不是恶意概率。剪枝受完整路径和预算约束，不能用一个单边阈值代替；真实同分不会被打散。

频率统计始终使用 `event.timestamp_ns < poi.timestamp_ns` 的全部同主机可用历史，不含同刻及之后事件，不将数据砍一半。切换案例或 POI 不改变这一条件。

## 从原始数据重建

原始日志、PDF、标签归档、SQLite 和运行缓存不提交到 GitHub；仓库提交模型、公开标签 ID 切片、实验报告和准备脚本。

```bash
python -m pip install flask numpy pypdf
# 可选：启用神经模型；CPU 可推理，训练可自动使用 CUDA
python -m pip install -r requirements-deep.txt
# 先生成默认案例及 GT 起点（PDF 与原始日志须已就位）
python webapp/scripts/prepare_optc.py
# 一次扫描到 12:20，生成全量历史/原始事件 SQLite
python webapp/scripts/prepare_optc_corpus.py
# 标签归档须放在 webapp/runtime/research/optc-labels/ 下
python webapp/scripts/prepare_examples.py
python webapp/scripts/prepare_tapas_reference.py
python webapp/scripts/evaluate_rule_lineage.py
# 仓库自带 checkpoint；仅需重新训练时运行下面一行
python webapp/scripts/train_deep_graph.py
python webapp/scripts/evaluate_deep_graph.py
python webapp/backend/app.py
```

默认数据路径 `/root/TAPAS-artifact/data/optc/logs/AIA-201-225*.json.gz`，默认真值 `OpTCRedTeamGroundTruth.pdf`。可在两个准备脚本通过 `--input` 指定文件；`prepare_optc.py --truth` 指定 PDF。频率索引与缓存通过 ID 校验。

公开标签归档来自固定提交：

```bash
mkdir -p webapp/runtime/research/optc-labels
curl -fL https://raw.githubusercontent.com/AT03380/optc-labels/64c9f9b2e1a15bf3c2789d89d93dc0724cb0d4fa/tasks/tasks.zip -o webapp/runtime/research/optc-labels/tasks.zip
curl -fL https://raw.githubusercontent.com/AT03380/optc-labels/64c9f9b2e1a15bf3c2789d89d93dc0724cb0d4fa/labels/malicious.zip -o webapp/runtime/research/optc-labels/malicious.zip
```

`prepare_optc_corpus.py` 不覆盖已有数据库；复用现有库即可。若需要改输入重新建库，可指定新的 `--output` 并相应更新本地 corpus manifest。训练、验证、校准、背景测试使用互不重叠的固定时间段。模型不读 GT；标签只在冻结后的评估使用。

## API

- `GET /api/datasets`：案例列表、全量计数与模型可用状态。
- `GET /api/datasets/<id>/view`：紧凑全量图、当前 POI、指标与攻击报告。`graph.nodes=[id,label,type]`，`graph.edges=[id,source_index,target_index,retained,score]`，`sampled=false`。
- `GET /api/datasets/<id>/edges?page=0&limit=20&q=&filter=all`：全量日志分页，支持 `retained/removed/attack/activity`；最大 100 条/页。
- `GET /api/datasets/<id>/events/<event_id>`：原始日志与判定详情。
- `POST /api/datasets/<id>/prune`：`poi_event_id` 必填；支持 `budget_ratio`、`selection_mode`、`attack_quantile`、`detector=rules|rules_legacy|neural`；`compact=true` 返回新版全量图。
- `GET /api/datasets/<id>/graph`：原有完整数据接口保留。
- `GET /api/datasets/<id>/decision-audit` / `attack-report`：下载可核验报告。

`NODOZE_DEMO_CACHE` 可指定单个缓存，此时不会自动加载默认多案例目录。

## 验证

```bash
python -m pytest -q tests/test_deep_graph.py tests/test_attack_inference.py tests/test_evidence_selection.py tests/test_rasp.py tests/test_rasp_diverse.py webapp/tests/test_optc.py webapp/tests/test_app.py
# 需 playwright 与 Chromium，运行中的服务使用上面的四个真实案例
python webapp/scripts/verify_optc_view.py
python webapp/scripts/verify_decision_audit.py downloaded-audit.json
python webapp/scripts/verify_attack_report.py downloaded-attack-report.json
```

浏览器回归覆盖四例全量计数、桌面/手机、节点和路径证据、查询分页、手动 POI、错误恢复、神经/规则切换与两种剪枝审计重放，结束后恢复初始案例设置。路径审计证明事件方向和时间一致，不能证明其恶意性或完整攻击链恢复。
