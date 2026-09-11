# 溯源调查评分、选边与阈值：文献及官方实现研读

检索和实现核对日期：2026-09-11。研读聚焦评分定义、判定层次、图连接约束与评估协议。
下载了下列论文全文，重点阅读对应方法与评估章节；官方代码以具体提交固定。
[来源清单](provenance-research-sources.json) 记录下载摘要和代码链接，论文与第三方源码仅保留在本地忽略的 research 目录。
本次没有训练或复现这些深度学习系统的完整实验，不能把文献中的数值当成本项目的对照结果。

## 1. 与本项目直接相关的证据

| 工作 | 核对位置与发现 | 本项目采用或拒绝的做法 |
|---|---|---|
| [NoDoze, NDSS 2019](https://kangkookjee.github.io/publications/nodoze-ndss2019.pdf) | §VI 的历史频率、路径传播、路径合并阈值与告警决策阈值是不同层次；§VI-F 的告警阈值需要有真/假告警标签的训练数据。 | 保留 POI 前历史；区分边证据与图选择，不能把边预算叫作恶意判定阈值。当前稀有度公式不是原文条件频率公式的复刻。 |
| [DEPIMPACT, USENIX Security 2022](https://www.usenix.org/system/files/sec22-fang.pdf) | §4.2–4.4 利用数据流/时间特征赋权，反向传播定位入口，再前向追踪；局部权重与最终调查子图是不同对象。 | 借鉴显式连接与时序见证；不声称本文的全局背景对比分就是 DEPIMPACT 局部权重，也不直接移植论文参数。 |
| [KAIROS, IEEE S&P 2024](https://arxiv.org/abs/2308.05034) | §4.3 的边重构误差、罕见性、窗口队列判定分层；窗口重构筛选与告警队列阈值不等价，后者使用良性验证数据。 | 保留“评分→资格→调查输出”的分层；不在当前攻击窗口上拟合一个分布阈值后宣称泛化。 |
| [NODLINK, NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-204-paper.pdf) | §III/V 把连接异常终端建模为在线 Steiner Tree 问题，理论界限对应其特定图问题和算法。 | 显式定义我们自己的路径束、成本和目标；不借用 NODLINK 的竞争比保证我们的预算子图质量。 |
| [ORTHRUS, USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf) | §4.4 用验证集最大损失阈值并进行异常聚类；§4.5 调查重构与节点检测分开。QoA 强调分析员需检查多少输出。 | 报告实际边/节点负担及参考覆盖；不把大量上下文都说成异常，不因参考保留率较高就忽略图尺寸。 |
| [Sometimes Simpler is Better, USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf) | SC2–SC5 指出阈值敏感、测试数据窥探、基线不公平和不稳定性问题；讨论不用单一阈值衡量检测潜力。 | 固定预算网格、报告全部 POI、同实际边数对比和同分敏感性；不靠测试标签选择“最好看”的阈值。 |
| [Testing for Outliers with Conformal p-values, Annals of Statistics 2023](https://www.gsb.stanford.edu/faculty-research/publications/testing-outliers-conformal-p-values) | 研究同分布参考样本及独立新样本下的 outlier p-value 和错误控制条件；有条件有效性与边际有效性不相同。 | 不把相互依赖、可能含攻击的 POI 前事件当成已知正常校准样本。当前不输出 conformal p-value 或 FPR 保证。 |
| [Data Provenance in Security and Privacy, ACM Computing Surveys 2023](https://doi.org/10.1145/3593294) | §3–5 区分 secure provenance 与 threat provenance；选择逻辑可复现，并不能自动证明日志来源完整可信。 | 记录源文件行号、版本和输入摘要；明确离线审计证明的是给定输入上的选择逻辑，而不是采集链可信性。 |

## 2. 官方开源代码核对

以下均为阅读与方法比较，没有复制其实现代码到项目。

- **Orthrus**：固定提交 `e7f25dfee1ddd182a955b88f8a90a8cbd4a8e543`。
  [`evaluation_utils.py`](https://github.com/ubc-provenance/orthrus/blob/e7f25dfee1ddd182a955b88f8a90a8cbd4a8e543/src/detection/evaluation_utils.py)
  的 `get_threshold`/`calculate_threshold` 从验证损失计算阈值；监督最优阈值另有函数，不能混为同一运行协议。
  官方 README 还披露过随机种子导致原结果不能精确重现的问题，因此本项目记录同分次序与敏感性。
- **NODLINK**：固定提交 `434dbe2d0be88bd034c4af0c819aed641d2b3758`。
  [`src/ETW/train.py`](https://github.com/httpsperanza/NODLINK/blob/434dbe2d0be88bd034c4af0c819aed641d2b3758/src/ETW/train.py)
  用加载的训练嵌入损失计算 90 分位数；README 要求把训练输出阈值传给运行脚本。
  这是具体实现的估计协议，不是任何环境下都能维持固定误报率的定理。
- **PIDSMaker**：固定提交 `ae1e9fd42604c769c01b2eaed6fb7f65e27f3cac`。
  [`evaluation_utils.py`](https://github.com/ubc-provenance/PIDSMaker/blob/ae1e9fd42604c769c01b2eaed6fb7f65e27f3cac/pidsmaker/detection/evaluation_methods/evaluation_utils.py)
  分开实现多种模型阈值，并计算攻击覆盖与 precision 的排序曲线。
  我们没有完整负标签，不能照搬 precision/ADP 名称，因此只报告“指标匹配密度”和“参考保留”。

## 3. 与我们当前问题的对应关系

同分至少有三种来源：数值格式合并、重复交互同特征、图结构对称。
更复杂的模型并不能保证每条边应当不同分；唯一 ID 加扰动也不提供安全语义。
因此保留真实同分，同时公开原始精度、同分组大小和同分时的资源分配规则。

对“超过阈值才保留”不能一概而论。检测阈值、候选资格、路径筛选、连接边保留和预算截断
是不同层次；论文中出现的统计阈值或图近似理论也各有适用前提。
我们的新规则检查数值误差界下的背景增益与严格时序见证，然后用明确的路径总收益/新增成本选边。
完整规则、证明范围和可执行审计见 [方法说明](evidence-selection-method.md)。

对研究结果的严谨性，至少需要分别回答：规则是否按定义执行、图是否保持所要求的连接、
预算是否真正相等、结论是否依赖同分次序，以及是否具有独立标注数据支持统计误差主张。
本次完成了前几项的实现与开发窗口实验；不能据此宣布达到论文级泛化验证。
