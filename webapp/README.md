# NODOZE · OPTC 手动 POI 剪枝与攻击调查

页面提供手动 POI、攻击节点与路径、剪枝前后对比、逐边评分和运行日志。
新增九位有效数字、真实同分组提示、逐边判定原因和可下载/离线重放的判定审计。
默认保持扩展上下文策略；证据子图是可选的精简调查模式，预算均为上限。
**实验未证明新模式普遍优于旧策略，小预算下有明显负结果，因此没有替换默认策略。**
[判定定义与证明范围](../docs/evidence-selection-method.md) ·
[论文与官方源码研读](../docs/provenance-selection-literature.md) ·
[同预算/同边数对照](../docs/evidence-selection-evaluation.md)。
默认从 TAPAS OPTC 数据读取 SysClient0201 的真实事件，根据项目内 Ground Truth PDF
明确指定 POI，使用所提供日志中该主机**全部严格早于 POI 的历史**统计频率。

## 启动

在项目根目录运行：

```bash
python -m pip install flask numpy pypdf
python webapp/scripts/prepare_optc.py
python webapp/backend/app.py
```

打开 `http://127.0.0.1:8000`。远程可通过 SSH 转发 8000 端口。
`NODOZE_WEB_HOST`、`NODOZE_WEB_PORT` 可调整监听配置。

脚本默认流式读取 `/root/TAPAS-artifact/data/optc/logs/AIA-201-225*.json.gz` 两个分片，
输入 `OpTCRedTeamGroundTruth.pdf`，并使用
[`poi/optc-day1-groundtruth-pois.json`](../poi/optc-day1-groundtruth-pois.json) 中的固定事件 ID。
原始数据、SQLite 频率索引和 Web 缓存不会上传到 GitHub；下载仓库后运行准备脚本生成。

```bash
python webapp/scripts/prepare_optc.py \
  --input /data/AIA-201-225.part1.json.gz /data/AIA-201-225.part2.json.gz \
  --truth OpTCRedTeamGroundTruth.pdf \
  --poi-config poi/optc-day1-groundtruth-pois.json \
  --poi a6da9327-470e-4bd0-b390-470ae80d8189 \
  --output webapp/runtime/optc-demo.json --budget 0.2 --selection-mode context
```

准备脚本检查 POI 的 UUID、主机、操作、时间、PID 和文件名或目标地址是否与配置相符。
缺少指定事件或 PDF 依据不匹配时直接报错，不自动退回“第一个匹配”。
缓存和索引通过版本 ID 对应；构建完成后原子切换缓存。

## 手动 POI 与频率

三个预设分别对应：下载 `runme.bat`、初始 PowerShell PID 5452 的 C2、提权后
PowerShell PID 2952 的 C2。默认用最后一项。配置记录精确原始事件时间和 PDF 依据；
PDF 的人工操作/check-in 时间与遥测连接时间不同，两者均保留。

选择预设后点击“应用 POI 并重新剪枝”，后端重新查询历史、打分、选边，并保存当前结果。
也可以输入候选窗口中的任意事件 ID，或在事件详情中点击“将选中事件设为 POI”。
自定义事件明确标为用户选择，不冒充真值支持。页面显示每次运行的计数和日志；
失败时保留上次有效结果。

频率条件为 `event.timestamp_ns < poi.timestamp_ns`，不含 POI 同刻及之后事件。
不再将时间窗口或记录条数对半切分。历史按原始事件 ID 去重，按事件时间查询，
不依赖分片文件顺序。页面显示真实历史起点、最后事件、截止时间、事件总数。
时间解析使用整数微秒转纳秒，避免浮点时间边界误差。

逐边展示：

- `historical_count`：POI 前同语义交互次数。
- `historical_frequency`：该次数 / POI 前全部有效历史事件数。
- `rarity = 1 / (1 + historical_count)`，用于现有 RASP 传播。
- 最终评分、评分条、当前页曲线、精确同分数量、逐边判定原因、拥有者锚点与完整见证、原始日志和源文件行号。

文件/进程按信息流两端标签和操作统计语义频次；网络按进程、方向、远端 IP、目标端口、
协议和操作统计，忽略临时客户端源端口。频率是历史经验频率，最终分数不是恶意概率。

## 评估范围

固定候选窗口是 2019-09-23 11:20–11:30（UTC−04:00），含 27,011 条
FILE / PROCESS / FLOW 事件。切换 POI 不改变候选集合；候选可以包含 POI 之后的事件，
但它们不进入历史频次计算。所有 POI 使用相同 RASP-D 配置：20% 硬预算、质量权重 0.05。
未按 Ground Truth 结果调预算或选择最优 POI。

PDF C2 IP / 文件名匹配仅供离线核对。匹配也可能包括正常程序对相关文件的访问；
未匹配事件不是已知正常事件，因此不报告完整攻击召回率、准确率或 F1。
报告同时提供排除固定保留 POI 后的指标和各攻击阶段参考保留情况。

最新全部预设结果见 [评估说明](../docs/optc-poi-evaluation.md) 和
[机器可读报告](../docs/optc-poi-evaluation.json)。这是单主机十分钟调查窗口，
并非完整 OPTC 或未见数据泛化评估。

上方计数覆盖完整候选图；图中为 80 条时间等间隔抽样加 Ground Truth POI 预设和当前 POI，未按保留结果选样。
两图使用相同坐标。评分表覆盖全部候选事件，每页 30 条。

## 验证与重新评估

```bash
python -m pytest -q webapp/tests tests/test_rasp.py tests/test_rasp_diverse.py tests/test_evidence_selection.py
python webapp/scripts/evaluate_optc.py
python webapp/scripts/evaluate_evidence_selection.py
# 从页面下载审计后
python webapp/scripts/verify_decision_audit.py downloaded-audit.json
# 运行服务后，需已安装 Playwright 和 Chromium
python webapp/scripts/verify_optc_view.py
```

测试覆盖严格 POI 边界、窗口之前历史、乱序/去重、多主机隔离、未来事件不泄漏、
POI 证据验证、接口持久化及失败恢复。浏览器测试覆盖 POI 切换重算、逐边频次、
图表一致性、搜索/分页、错误恢复和手机布局。

旧 THEIA 实验和准备脚本保留，默认页面使用新的 OPTC 缓存。

## 两种调查模式

- **扩展上下文**：保留旧 RASP-D 输出行为，含很小的传播保底分。逐步记录锚点优先级、
  完整路径新增成本、接受/拒绝依据；“考虑时超预算”与“预算耗尽前未轮到”明确区分。
- **证据子图**：背景增益须超过 PPR 残差误差界才能主动作为证据锚点；零证据事件只能作为
  路径连接边。按整条新增路径的目标收益/新增成本选择，证据已保留完时停止。
  同时给出自定义优化目标的松弛上界；该上界不能解释为攻击召回率保证。

两种模式都能下载 `/api/datasets/optc-0201/decision-audit` 并离线重放。
“保留”不等于“恶意”，“删除”不等于“正常”，也不能由一个通用单边分数阈值决定。
当前默认 POI：扩展上下文 5,402 条 / 211 个参考匹配；可选证据子图 498 条 / 183 个参考匹配。
在相同 498 条边下旧策略也保留 183 个参考匹配，因此不能声称新模式在该对照中提高召回。


## 攻击节点与路径

应用 POI 会同时运行独立于剪枝预算的进程级推断。页面支持按 PID/UUID 搜索、显示未判定节点、点击节点查看命令与历史异常证据、切换完整事件路径、下载调查报告。默认 90% 节点异常分位线可切换 80/95/99%，它是同窗口调查启发式，不是恶意概率或统计误报率。

推断攻击进程、人工 POI、路径连接进程、文件/网络资源分别显示。共享缓存等文件依赖标为待确认，不能当作完整攻击链或提权证明。下载图中的路径不受剪枝抽样限制。

新增接口：

- `POST /api/datasets/<id>/prune` 接受 `attack_quantile`，返回 `attack` 字段；失败不会覆盖旧结果。
- `GET /api/datasets/<id>/attack-report` 下载节点、路径、支持事件及独立评估。

```bash
python webapp/scripts/verify_attack_report.py /path/to/optc-attack-report.json
python webapp/scripts/evaluate_attack_inference.py
```

默认提权 C2 POI 推断 PID 5452、4632、2952。公开标注基准中 TP=3、FP=0、FN=5、TN=105，Precision=100%、Recall=37.5%、F1=54.55%。高精确率仅是本窗口的 3/3；仍有明显漏检。PDF 已知代理找回 2/2，与公开标注口径分开。完整攻击路径 Precision/Recall 未知。

仓库包含当前固定窗口的公开标签 ID 切片及来源哈希；全体事件/进程 ID 不匹配时不套用。原始日志与下载的标签归档仍在忽略目录。

[方法与论文依据](../docs/attack-inference-method.md) · [完整实验及边界](../docs/attack-inference-evaluation.md)
