# NODOZE · OPTC 手动 POI 剪枝

页面保留手动 POI、剪枝前后对比、逐边评分和运行日志。
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
  --output webapp/runtime/optc-demo.json --budget 0.2
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
- 最终评分、评分条、当前页曲线、保留原因、原始日志和源文件行号。

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

上方计数覆盖完整候选图；图中按时间等间隔独立抽取 80 条事件，不按分数或保留结果选样。
两图使用相同坐标。评分表覆盖全部候选事件，每页 30 条。

## 验证与重新评估

```bash
python -m pytest -q webapp/tests tests/test_rasp.py tests/test_rasp_diverse.py
python webapp/scripts/evaluate_optc.py
# 运行服务后，需已安装 Playwright 和 Chromium
python webapp/scripts/verify_optc_view.py
```

测试覆盖严格 POI 边界、窗口之前历史、乱序/去重、多主机隔离、未来事件不泄漏、
POI 证据验证、接口持久化及失败恢复。浏览器测试覆盖 POI 切换重算、逐边频次、
图表一致性、搜索/分页、错误恢复和手机布局。

旧 THEIA 实验和准备脚本保留，默认页面使用新的 OPTC 缓存。
