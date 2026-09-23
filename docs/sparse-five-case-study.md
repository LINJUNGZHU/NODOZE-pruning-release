# NODOZE 五个案例的依赖图实验（开发集）

## 案例、POI 和数据来源

实验只覆盖用户图中的五行。原始事件来自 [DARPA Transparent Computing E3 发布清单](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md)所列流；攻击时间和行为依据本地官方 `TC_Ground_Truth_Report_E3_Update.pdf`（SHA-256 `eccf295b566b8e981fe90e0f1aea61116bd5a5694441396af63f22a914cbc39c`）。POI 是先从报告中的文件或通信目标定位，再解析到原始 CDM 事件的调查种子，没有调用外部告警。所有 POI 都是利用真值选定的 **oracle POI**，不能宣称自动告警发现能力。[清单](../configs/sparse_five_cases.json)记录原始文件、时间段、数据库、POI 和结果账本。

| 图中的行 | 本次原始流 | 官方报告阶段 | 本次 POI | POI 数 |
|---|---|---|---|---:|
| Five Dir Case 1 | FiveDirections，4 月 9 日 | §4.4，Excel 宏和 PowerShell 写入 `update.ps1` | 最后一次写入 `update.ps1` | 1 |
| Five Dir Case 3 | FiveDirections，4 月 12 日 | §3.10，浏览器扩展写入 `hJauWl01` | 最后一次写入 `hJauWl01`；优化方案另加报告中的 C2 `CONNECT` | 1 / 2 |
| Theia Case 1 | THEIA，4 月 10 日 | §3.3，Firefox 后门 | `/home/admin/clean` 及同阶段两个报告锚点 | 3 |
| Theia Case 3 | THEIA，4 月 12 日 | §3.11，浏览器扩展 | `/tmp/memtrace.so` 及同阶段两个报告锚点 | 3 |
| 图中 Theia Case 5 | **TRACE**，4 月 13 日 | §4.9，Pine 邮件附件 | 最后一次写入 `/tmp/tcexec` | 1 |

末行的名称存在原文冲突：[SPARSE 的表](https://arxiv.org/html/2405.02629v1)写作 “THEIA Case 5”，而 [DEPIMPACT 论文](https://people.cs.vt.edu/penggao/papers/depimpact-security22.pdf)及其 [USENIX 工件](https://zenodo.org/records/5559214)的第五案为 `trace-case5`，POI 是 `/tmp/tcexec`。工件还分别列出 FiveDirections Case 1 的 `update.ps1`、Case 3 的 `hJauWl01`、THEIA Case 1 的 `/home/admin/clean` 和 Case 3 的 `/tmp/memtrace.so`；据此将图中末行**推断**映射到 TRACE Case 5。这个推断没有 SPARSE 作者的事件 ID 映射确认。[工件核对记录](depimpact-artifact-case-map.json)保存每个 `.property_case*` 和 DOT 的 SHA-256。早先按字面 THEIA 4 月 13 日和 FiveDirections 4 月 11 日 Firefox 攻击做的探索，不进入五案目标表。

## 标注与指标的边界

[SPARSE 论文](https://arxiv.org/html/2405.02629v1)的五行关键事件数是 8、9、8、8、5，但没有公布这些事件的 CDM ID。USENIX 工件的 `criticalEdge` 标的是**预处理 DOT 图的实体对**。一个 DOT 边会合并多个原始事件，例如 FiveDirections Case 1 的两个关键实体对展开为 7 次 `WRITE` 和 13 次 `RECVFROM`；TRACE 的三个实体对展开为 104 条候选图边。因此下表的已知正例不是 SPARSE 的关键事件集，也不能用 20、13 或 104 代替论文的 8、9 或 5。实体对到 CDM 的展开依据主机、端点、事件类型、秒级时间和聚合字节数，详见各 [正例文件](../poi/fivedirections-e3-case1-phishing-depimpact-pair-events.json)、[Case 3 正例](../poi/fivedirections-e3-case3-depimpact-pair-events.json)和 [TRACE 正例](../poi/trace-e3-case5-depimpact-pair-events.json)。THEIA 1/3 使用本地检测器节点真值与报告窗口推导的正例，范围更宽。

这些参考集都是**部分正例**，不含完整负例。未标记的保留边应记为“未审查”，不能计作 FP；未标记的删除边也不能计作 TN。严格评估器仅在参考文件声明事件级完整标注且绑定候选账本 SHA-256 时填写 TP、FP、FN、TN、Precision、Recall、F1、FPR。当前五案的这些字段全部为 `null`。下面的 `已知正例命中`只是针对各自参考集的开发集覆盖，不等同于论文 Recall。POI 命中单列，避免把必保种子算成发现能力。完整数字见 [基线审计](sparse-five-case-results.json)、[优化审计](sparse-five-optimized-results.json)及 [CSV 指标表](sparse-five-performance-table.csv)。

THEIA 1/3 的工件 DOT 关键边也已按实体对和时间定位，但部分网络边在原始 CDM 中对应大量同秒事件，无法唯一反解为论文所需的事件 ID；因此没有把这些含糊的配对冒充完整真值。

## 实测结果

基线为本仓库 PS-RDP 在本次候选图的 20% 预算；优化方案为 RASP-D q=0 加有限的 POI 语义延续。优化器读取 POI、候选图和原始 CDM 字段，不读取攻击标签或外接告警。每案窗口和候选图由清单中的固定账本定义，不能把下面的边数与论文的 `#E` 当作相同粒度的独立复现。

| 案例 | 候选边 | 基线 #E | 基线已知正例命中 | 优化 #E | 优化已知正例命中 | 优化非 POI 正例命中 | 图中 SPARSE #E |
|---|---:|---:|---:|---:|---:|---:|---:|
| Five Dir Case 1 | 466,257 | 93,251 | 7/20 | **23** | **20/20** | 19/19 | 11 |
| Five Dir Case 3（基线 1 POI；优化 2 POI） | 424,245 | 84,849 | 5/13 | **39** | **13/13** | 12/12（仅排除落在参考集内的 1 个 POI） | 40 |
| Theia Case 1（3 POI） | 898,253 | 179,650 | 405/25,217 | **179,650** | **521/25,217** | 518/25,214 | 106 |
| Theia Case 3（3 POI） | 1,132,218 | 226,443 | 664/870 | **226,443** | **870/870** | 867/867 | 129 |
| 图中 Theia Case 5（推断为 TRACE） | 137,762 | 27,552 | 104/104 | **135** | **104/104** | 103/103 | 7 |

Five Dir Case 3 的 20% 基线只使用写文件 POI；优化时加入报告中的 C2 `CONNECT`，因此两列不是严格等信息对比。两个 POI 的 20% 基线也已经覆盖 13/13；在 **39 边**预算下，未加桥接规则的选择只保留 2/13，加入同 socket 接收、共享文件读/打开及一个进程派生桥后才达到 13/13，详见 [配对审计](sparse-five-case3-depimpact-pair-audit.json)。优化图有两个 UUID 连通分量，其中两 POI 与全部 13 个正例处于同一分量；另一分量只有一条额外边。

Five Dir Case 1 和 TRACE 的 `file_poi_io_origin` 规则从写文件 POI 沿一个父进程与最高流量 socket 的近邻读取追溯来源，分别在 23 和 135 边预算下覆盖工件展开的正例。两幅优化图各只有一个 UUID 连通分量。该规则和预算是在这些案例上分析后确定的，因此结果是**开发集拟合**，不是独立测试。THEIA Case 1 的增益有限；THEIA Case 3 的 870/870 仍需 226,443 条输出边，远未达到图中 129 边的紧凑度。优化不能据此称为顶会水平或超越 SPARSE。

## 复现与进一步验证

在本工作树运行：

```bash
python -m scripts.run_sparse_five_audit \
  --inventory configs/sparse_five_cases.json \
  --output docs/sparse-five-case-results.json
python -m scripts.run_sparse_variant_audit \
  --variants configs/sparse_five_optimized_variants.json \
  --output docs/sparse-five-optimized-results.json
python -m pytest -q
```

原始数据和结果账本在清单列出的本机绝对路径；Git 只保存代码、配置、POI、标注映射、审计结果和 SHA-256，不提交大型 CDM/VM 文件。若要得到可发表的同表 FP/FN/Precision/Recall/F1，需取得或独立逐事件复核五案在**同一候选图**中的完整关键边，并标注所有未审查边。随后冻结 POI 协议与规则，在未用于调参的攻击上测量，与相同事件粒度和预算的基线比较，并报告速度、内存、消融和置信区间。当前数据不足以作出顶会级性能结论。
