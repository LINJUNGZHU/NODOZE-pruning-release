# 当前默认：RASP-D q=0 / 20% 边预算

2026-09-10 按用户要求从已测试配置中选一个统一默认。比较口径：四个开发案例、相同完整候选图和 POI、相同 20% 原始事件边上限，以四案例等权平均攻击事件召回选型，同时检查参考短链保留。

|统一配置|四案例平均召回|
|---|---:|
|RASP-D q=0|95.8743%|
|RASP-D q=0.05|95.7594%|
|RASP-D q=0.25|95.5870%|
|双路 RRF|95.5018%|
|原 RASP|95.1754%|
|三路 RRF|88.1980%|
|纯 PPR|77.2288%|

选中的统一配置：THEIA 100%、CADETS-06 100%、CADETS-12 99.16%、CADETS-13 84.34%；短参考链分别 3/3、3/3、8/8、3/3。
不是每个案例单独最优，也不是所有预算最优，更不是所有可能算法中的最优；不把此开发集事后选型称为独立泛化测试。

`q=0` 仅取消选择目标里的线性重复质量项，**没有取消稀有度、重要性或图传播**：每条边的重要性仍由 RASP 算出，再进入质量加权的边际收益递减函数。
参考链完整不等于完整攻击事件全部保留，CADETS-13 仍有漏失。

网页默认已切换到 `rasp_d0@0.2`，显示对应逐边决策和锚点收益。旧 RASP 仍可选。1%、5%、10% 只作为实验，不承诺此配置在低预算更好。
默认是离线调查剪枝配置；流式 `run_stream_rasp.py` 不自动改为本算法，因为该流水线的传播和窗口语义不同，不能直接搬用本表性能。
历史文档中“默认仍为 RASP”描述的是当时状态，以本页为准。

## 默认运行入口

```bash
cd /root/NODOZE-pruning-release
run_id=$(date '+%Y-%m-%d_%H-%M-%S')
setsid -f python -u -m scripts.run_selected_rasp \
  --ledger output/tc/poi-prefix-sweep/2026-09-09_10-47-48/scenario-12/poi-prefix-8-ledger/edge-scores.jsonl.gz \
  --reference output/tc/poi-prefix-sweep/2026-09-09_10-47-48/scenario-12/fixed-reference.json \
  --output "output/tc/selected-rasp-CADETS-12-${run_id}" \
  > "logs/selected-rasp-CADETS-12-${run_id}.log" 2>&1 < /dev/null
```

入口固定使用 `configs/rasp_selected.json`；主决策为 q=0、20%，同时输出其他预算/权重消融用于审计。旧实验入口的配置保持不变，防止历史复现含义被修改。
