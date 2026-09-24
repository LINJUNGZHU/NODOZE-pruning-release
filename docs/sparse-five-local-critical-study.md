# 五案的本地 SPARSE 式关键边实验（开发集）

## 关键边怎样确定

按 [SPARSE 论文 §V-A2、§IV-D](https://arxiv.org/html/2405.02629v1)描述的流程，从调查 POI 回溯，结合攻击报告中的 IOC 和步骤判定关键事件。论文的人工逐事件真值没有公开。本实验独立制作一份**本地操作性参照**，不声称复原论文的标注。

本地官方报告是 `TC_Ground_Truth_Report_E3_Update.pdf`，SHA-256 为 `eccf295b566b8e981fe90e0f1aea61116bd5a5694441396af63f22a914cbc39c`。[选择清单](../configs/sparse_five_local_critical_choices.json)固定了 45 条代表事件的 ID、报告阶段、理由；[逐边参照](sparse-five-local-critical-reference.json)同时保存主机、纳秒时间、关系、方向端点、PDF 页码、候选账本 SHA-256。先用[不含检测器决策的审查包](sparse-five-critical-review/five-dir-case-1.json)及其余四案的同目录文件选边、提交选择清单，再计算任何对比成绩。

参照生成器把代表事件扩展为同主机、同方向端点、同事件类型、时间相差不超过 10 秒的候选图并行事件。这样把论文的 10 秒并行边合并思想映射到本仓库逐事件账本；两者的图粒度仍不相同。扩展后的关键事件数分别为 38、15、239、229、31。完整选择理由和每个扩展组的 ID 均可检查。`LINEAGE:` 前缀的进程派生是本仓库候选图构造的合成边，不能当成原始 CDM 事件。图中最后一案映射到 TRACE Case 5 仍是根据 DEPIMPACT 工件作出的推断，详见[五案来源说明](sparse-five-case-study.md)。

## 计算约定与结果

为能做实验性比较，这张表**暂把候选图里没有进入本地参照的边视为负例**；据此计算 `proxy_FP`、`proxy_FN`、Precision、Recall、F1、FPR、FNR。它是封闭世界代理指标：未列入参照的边可能仍与攻击相关，尤其大规模 THEIA 图的 `proxy_FP` 会被高估。FPR 用 `FP/(FP+TN)`，FNR 用 `FN/(FN+TP)`。这张表中的任何数字均不能拿来和论文表中的 FP、FN、Precision、Recall、F1 直接比较；论文等价字段在[完整 CSV](sparse-five-local-critical-performance.csv)中仍为 `NA`。每案候选边和 TP/TN、指标的完整精度及决策文件哈希在[机器可读结果](sparse-five-local-critical-results.json)中。

| 案例 | 方法 | #E | 代理 FP | 代理 FN | 代理 Precision % | 代理 Recall % | 代理 F1 % | 关键组命中 | 攻击阶段命中 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Five Dir Case 1 | 20% 基线 | 93,251 | 93,233 | 20 | 0.019 | 47.37 | 0.039 | 2/9 | 1/3 |
| Five Dir Case 1 | 本地优化 | **51** | 13 | **0** | **74.510** | **100** | **85.393** | **9/9** | **3/3** |
| Five Dir Case 3 | 双 POI 20% 基线 | 84,849 | 84,837 | 3 | 0.014 | 80.00 | 0.028 | 4/7 | 2/3 |
| Five Dir Case 3 | 双 POI 本地优化 | **49** | 34 | **0** | **30.612** | **100** | **46.875** | **7/7** | **3/3** |
| Theia Case 1 | 20% 基线 | 179,650 | 179,634 | 223 | 0.009 | 6.69 | 0.018 | 11/12 | 6/6 |
| Theia Case 1 | 20% 优化 | 179,650 | 179,601 | 190 | 0.027 | 20.50 | 0.054 | 12/12 | 6/6 |
| Theia Case 3 | 20% 基线 | 226,443 | 226,214 | 0 | 0.101 | 100 | 0.202 | 9/9 | 5/5 |
| Theia Case 3 | 20% 优化 | 226,443 | 226,214 | 0 | 0.101 | 100 | 0.202 | 9/9 | 5/5 |
| 图中 Theia Case 5（TRACE 映射） | 20% 基线 | 27,552 | 27,523 | 2 | 0.105 | 93.55 | 0.210 | 6/8 | 5/6 |
| 图中 Theia Case 5（TRACE 映射） | 本地优化 | **144** | 113 | **0** | **21.528** | **100** | **35.429** | **8/8** | **6/6** |

Five Dir Case 1 的 51 边图从文件写入 POI 保留同名路径别名的早期写入、后续读取、下载 socket 的首次发送、反连后的 shell 派生；Case 3 的 49 边图从两个报告 POI 保留写文件后的执行及两条汇入同一子进程的派生；TRACE 的 144 边图保留失败 shell 连接后的 `/bin/sh` 派生。规则只看 POI、事件时间、主机、端点及语义字段，不读外接告警或参照标签；但**规则和预算在这五案上分析后调整过**，因此不是独立测试。Case 3 的主表基线和优化图都使用两个报告 POI；另将原来一个写文件 POI 的基线列入[机器可读结果](sparse-five-local-critical-results.json)的 `one_poi_ablation`，其命中为 3/15 事件、2/7 组、1/3 阶段。新规则和输出路径在[本地优化配置](../configs/sparse_five_local_critical_variants.json)中。

THEIA 1/3 的 20% 决策是本仓库先前保存的历史运行。THEIA 1 的报告保留了旧版选择器源文件 SHA-256；THEIA 3 的决策账本没有同类实现报告。这两行的候选账本与决策 SHA-256 已锁定并核对，但当前代码版本不能直接宣称重建了这两份历史决策。

THEIA 的逐事件数与组命中必须分开看：Case 1 一个 shellcode `RECVFROM` 组有 223 条并行事件，20% 优化图只保留其中 33 条，因此尽管 12/12 组、6/6 阶段均命中，事件级代理召回仍为 49/239。Case 3 的 20% 图保留 229/229，但输出 226,443 条边。另测 0.1% 和 1% 的 RASP-D 预算：Case 1 分别输出 898、8,982 边，两者只命中 9/12 组和 5/6 阶段；Case 3 分别输出 1,131、11,321 边，两者只命中 6/9 组和 4/5 阶段。Case 1 在 0.1% 预算上再启用文件 IO 来源追溯，输出 896 边、命中 12/239 事件，仍未找到早期浏览器连接阶段。更小图尚未同时达到完整阶段覆盖。

## 复算

在此工作树执行：

```bash
python -m scripts.validate_sparse_local_critical_edges \
  --choices configs/sparse_five_local_critical_choices.json \
  --output docs/sparse-five-local-critical-reference.json
python -m scripts.evaluate_sparse_local_reference \
  --reference docs/sparse-five-local-critical-reference.json \
  --choices configs/sparse_five_local_critical_choices.json \
  --inventory configs/sparse_five_cases.json \
  --variants configs/sparse_five_local_critical_variants.json \
  --output docs/sparse-five-local-critical-results.json
python -m scripts.export_sparse_local_reference_csv \
  --results docs/sparse-five-local-critical-results.json \
  --output docs/sparse-five-local-critical-performance.csv
python -m pytest -q
```

原始账本和大决策文件在配置指定的本机路径，Git 保存小型配置、事件 ID、标注证据、结果和哈希。本地参照并非穷尽的逐边人工审查，五案都是开发集，候选图与 SPARSE 的输入图也不一致；所以目前不能据这些代理结果宣称复现或达到论文的性能，更不能作顶会级泛化结论。
