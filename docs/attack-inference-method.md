# 攻击节点推断、路径输出与准确率口径

当前版本 `attack-hypothesis-v1` 新增了独立于剪枝的进程级攻击假设与可核验的事件路径。它是适合当前数据条件的透明混合启发式，不是复现或训练完成的 ORTHRUS / KAIROS 模型，也不是已经证明优于这些系统的新检测器。

## 从研究到实现

| 论文 / 官方代码 | 研读内容与本项目决定 |
|---|---|
| [ORTHRUS · USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/jiang-baoxiang) / [官方源码](https://github.com/ubc-provenance/orthrus) | §4.4–4.5 分开节点异常检测与攻击重建。源码 `src/detection/node_evaluation.py` 从验证集确定阈值，`attack_reconstruction/tracing_methods/depimpact.py` 从预测节点追踪。本项目也分层，但没有独立正常训练/验证集，不能声称复现其校准或误报率。 |
| [NODLINK · NDSS 2024](https://www.ndss-symposium.org/ndss-paper/nodlink-an-online-system-for-fine-grained-apt-attack-detection-and-investigation/) / [官方代码](https://github.com/httpsperanza/NODLINK) | 检测终端与连接它们的图节点并不等价。页面区分推断攻击进程、连接进程和关联资源；不移用其 Steiner 算法近似保证。 |
| [KAIROS · IEEE S&P 2024](https://arxiv.org/abs/2308.05034) | 从事件异常到检测输出再到调查图需要独立定义。本项目不把剪枝保留当作恶意标签。 |
| [Attack structure matters · Computers & Security 2025](https://doi.org/10.1016/j.cose.2025.104578) / [SDTED 作者实现](https://github.com/msrom/SDTED) | §3–5 指出节点集合重叠不能代表攻击结构正确。检查了 `Graph.py` 的出邻居建模和 `SDTED_utilities.py` 的节点指标对照；本项目增加方向、严格时间、原始事件和角色校验。缺少完整 GT 图，不能计算可信的 SDTED 或完整路径 precision/recall。 |
| [Sometimes Simpler is Better · USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/bilot) | 固定分位线敏感性实验，报告行为/异常消融及负结果；不以本窗口结果选择最优阈值。 |
| [SigmaHQ 官方编码命令规则](https://github.com/SigmaHQ/sigma/blob/5c9b21756f4e3ba137c1773ac9ba5a8332188961/rules/windows/process_creation/proc_creation_win_powershell_encode.yml) / [MITRE PowerShell](https://attack.mitre.org/techniques/T1059/001/) | 命令行行为可以解释，但编码本身不证明恶意。这里自主实现编码参数与隐藏窗口的联合观察，并要求后续行为及 POI 调查关联；没有复制 Sigma 规则或实现其完整过滤集。 |
| [OpTC 数据官方勘误](https://github.com/FiveDirections/OpTC-data/blob/5b108604f11f767aa11ea79ff827595f3fad15fd/errata.md) | 原始数据有重复进程对象。保留 UUID 身份，不能把 PID 相同就当作同一节点。 |
| [公开 OpTC 标注及作者源码](https://github.com/AT03380/optc-labels/tree/64c9f9b2e1a15bf3c2789d89d93dc0724cb0d4fa) | 这是 CIoT 2024 数据标注工作，不冒称顶会检测器。研读五类标签定义、`matcher.go` 和标注勘误；从公开领域的标签提取当前窗口的独立评估切片。 |

论文 PDF SHA-256、源码版本和文件清单见 [来源清单](attack-inference-sources.json)。研究下载与完整源代码保存在忽略的 runtime 下；没有把外部代码、论文或原始数据打包入仓库。

## 输入和边界

输入是当前候选窗口的全部事件、用户明确选择的 POI，以及严格早于 POI 的历史频次与背景传播证据。会观察 POI 之后的候选事件，因此是**回溯调查**，不是在 POI 时刻立即可用的在线告警。

调用链为：`rescore → infer_attack → evaluate_attack`。检测函数不读取 Ground Truth、参考 IP/PID、剪枝保留标记、剪枝预算或显示分数。原始 IP/文件等属于历史语义签名，但没有攻击目标名单。GT 仅在检测完成后做核验。

当前分类单位是**进程对象 UUID**。文件与网络对象可作为路径资源输出，不能仅因与攻击进程接触便判其恶意。CREATE 记录的 `pid/image_path` 指子进程，`ppid/parent_image_path` 指父进程；其他操作按 actor 取进程元数据。不会跨 UUID 合并同 PID，且会保留别名/缺失身份导致的局限。

## 节点规则

两条通道取并集，每条都有原始事件证据。默认配置在公开标注比对前固定；没有用测试标签调参。

1. **联合行为**：进程 CREATE 中 PowerShell 映像带编码命令参数和隐藏窗口参数，随后在严格更晚时刻发生出站 FLOW 或创建子进程，同时该进程有 POI 时序调查关联。命令行可能被遥测截断；只识别可见参数，不执行命令，也不把残缺 Base64 补成完整攻击代码。此通道覆盖有限，普通编码/隐藏管理任务也可能造成误报。
2. **历史异常**：仅使用背景增益超过数值误差界、且有 POI 时序见证的事件。每条事件权重 `w(e) = sqrt(contrast(e) / (1 + pre_poi_count(e)))`。同一进程同语义签名取最大值，不用重复遥测堆高分数。按前三个签名最大权重之和除以固定分母 3 得到节点分；少于三个签名不重新缩小分母。至少两种签名才参加当前窗口的经验分位线比较。默认严格超过 90% 分位线，80/95/99% 用于敏感性实验，同分不拆分。

分位线是**同窗口调查启发式**，不具备独立正常验证集阈值的统计意义，样本量会公开展示。它不是恶意概率，不对应 10% 误报率。当全体同分或证据不足时可以不报。POI 端点有独立标记，但不会被强制设置为攻击预测；评估同时报告排除 POI 节点的结果。

异常分只描述异常通道。联合行为通道可能让低异常分的节点被预测；网页显示两个通道的具体依据，不把它们伪装成单个概率。

## 路径重建与证据强度

对推断攻击进程构造两类输出：

- **启动/通信轨迹**：向前追溯实际 PROCESS_CREATE 的祖先，再接创建后第一个真实出站网络事件。最多显示 12 层启动祖先，若达到上限显式标记截断。祖先进程保留为连接角色。
- **节点间关联**：从节点第一个支持证据时刻之后，按事件时间扫描，构造首次到达的有向路径。相同时间批次同时更新，保证每一步严格更晚；这是确定性的可达见证，不是最短/最可能攻击路径的保证。

允许 PROCESS_CREATE、FILE_READ/WRITE/CREATE 和 FLOW 信息流；PROCESS_OPEN/TERMINATE 本身不能证明信息传递，不用于连接。原始 `source → target` 方向不能翻转来凑路径。

节点间经过文件的路径标记 `dependency_only`。例如两个进程先写后读 `ModuleAnalysisCache` 只说明共享缓存的遥测依赖，**不能证明载荷传递、UAC 绕过或完整提权链**。页面把这种关联与真实启动/通信轨迹区分。叙事阶段连接即使有遥测路径也不会标为攻击机制已验证；缺失边不自动补造。

每条路径输出节点 UUID、原始事件 UUID、时间、方向、节点角色和完整事件列表。报告下载端点为 `/api/datasets/<id>/attack-report`。离线运行：

```bash
python webapp/scripts/verify_attack_report.py /path/to/optc-attack-report.json
```

验证器重新解析所附原始记录，检查事件字段、严格时序、方向、路径节点序列、证据并集和角色分离。它证明的是内部一致性，不证明日志真实性、事件恶意性、选择最优性或 GT 正确性。

## 两套评估必须分开

**用户 PDF 口径**：用主机、日期、PID、映像与实际 C2 actor UUID 绑定两个已知代理；不按 PID 合并重复对象。其它进程保持未标注。可报告已知正例找回、未核验预测及精确率区间；无法据此计算整体 Accuracy/F1。两个 C2 通信片段可核验，不是完整攻击路径真值。

**公开标注基准**：固定 `AT03380/optc-labels` 版本，当前窗口共 113 个进程对象，其中 8 个 process 粒度恶意对象、105 个按作者补集约定计为正常的对象。`event` 粒度恶意记录不扩散为整个进程恶意；`invalid` 条目忽略；冲突标记为未知。本地匹配 735 条已标注恶意事件。节点和事件标签各自独立构造，不能把恶意事件两端都设成攻击节点。

这是能计算混淆矩阵的公开基准口径，但它的正常补集并非独立逐节点人工验证。作者还披露了错误父子关联、conhost 标注不一致等问题。保留原口径和勘误链接，不为提高结果擅自删除困难节点。

整体正确率 `Accuracy=(TP+TN)/N` 在正常对象占多数时会很高，必须连同 Precision、Recall、F1、TP/FP/FN/TN 展示。路径上的进程覆盖、路径事件 precision/recall、以及完整攻击路径正确率是不同指标。简短摘要保留很少事件本就会有很低的事件召回，不能用“路径有向有效”充当攻击路径识别正确。

公开标签切片的范围由全体事件 ID 和进程 ID 的 SHA-256 锁定；更换窗口时不套用旧标签。构造脚本为 `webapp/scripts/prepare_attack_reference.py`，只使用下载的 tasks/malicious 两个归档，产物包含归档哈希、版本、标注约定和来源。检测不会读取此文件。

这仍是单主机、单窗口的开发实验，三个 POI 不是三个独立测试集。无法据此给出跨主机泛化、完整攻击链恢复或误报率保证。[实测结果与消融](attack-inference-evaluation.md)报告已有结果和漏检。
