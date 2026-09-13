# 社交网络传播方法与 NODOZE 攻击调查的对应关系

适合继续推进的方向是**关系与时间约束下的反向溯源、正向证据解释，以及长事件链的分组计算**。传播模型负责回答“哪些早期事件可能解释这组后续活动”，攻击判定仍须结合行为证据与独立标注。不能把社交用户受到影响，直接解释成主机进程已经失陷。

本文覆盖截至 **2026-09-13** 可核验的近期工作，核心来源为 WWW 2026、KDD 2025、IJCAI 2025、The VLDB Journal 2026，并补充与源定位直接相关的 TNSE 2026 作者全文。会议名称以论文首页或官方目录为准，网页抓取时间不作为发表日期；没有核实的“最新顶会”称号不采用。

本轮完成文献与部分作者代码核查、迁移设计、数据准入清单和 PDF 评估入口的暂停机制。**下文新传播算法属于待验证方案，尚未替换线上评分或检测器，也没有新的性能提升数字。**

## 论文与项目的对应关系

| 论文 | 出版与读取范围 | 最有价值的对应关系 | 当前取舍 |
|---|---|---|---|
| Many Hands Make Light Work: Group-based Information Diffusion Prediction over Long-Context Cascades（GRID） | WWW 2026；取得 10 页作者 PDF，阅读方法、评估和误差界条件 | 长链分组，减少全体事件两两计算 | 优先借鉴计算结构；保留原始事件可展开性 [^1] |
| Efficient Sphere-Effect Based Information Diffusion Prediction on Large-scale Social Networks（SILN） | KDD 2025；取得 11 页作者 PDF，阅读采样、关系表示和评估 | 区分结构邻接和历史互动，按关系筛选局部上下文 | 优先借鉴关系分离与局部提取 [^2] |
| A Generalized Diffusion Framework with Learnable Propagation Dynamics for Source Localization（GDFSL） | IJCAI 2025 主会；取得 9 页官方 PDF，阅读训练、推断和实验 | 由观测传播反推源头 | 借鉴反向推断目标；不直接搬用传播模拟器 [^3] |
| Efficient and cost-effective influence and blocker minimization | The VLDB Journal；2026-09-03 正式发表，取得 26 页 PDF，阅读目标、算法、界与实验 | 多路径组合效应、上下界和独立抽样核验 | 优先借鉴证明框架；不把阻断目标当成证据保留目标 [^4] |
| PDSL: Propagation Dynamics Aware Framework for Source Localization | TNSE 2026；阅读作者 HTML 全文的方法与实验；arXiv 关联正式 DOI，IEEE 正文未取得 | 候选源分布与正向传播重建联合检查 | 中期学习方案；需要可靠训练状态和源头标签 [^5] |

### GRID：分组可以帮助大图，但分组本身不证明攻击

GRID 在历史级联上学习群组表示，动态分组后做带群组大小权重的注意力。其表示误差界要求有界输入、正交投影和受控组内误差；关于长度的线性开销还依赖固定的小群组数、表示维度和聚类迭代成本。真实数据表最大级联长度为 8,188，更长序列用于合成规模实验。它评价未来群体的 Recall@K/NDCG@K，不是恶意节点分类。[^1]

**本项目的迁移判断：**把进程生命周期内相同关系的连续活动作为候选计算单元，先组间排序，再展开关键组。当前一分钟端点聚合只是展示压缩，尚未实现 GRID 的学习分组。组内必须保留事件 ID、先后顺序和进程身份；不能把同组的正常子活动全部判攻击。若采用学习表示，需实际测量组内误差，不能直接照搬论文误差界。

### SILN：传播关系应分开建模

SILN 分开处理关注、被关注和历史互动，使用方向区分的随机游走与互动采样提取级联局部子图，并结合结构与时间视角。其关系编码用于降低重复存储和计算；论文的社交任务仍是后续参与者预测。[^2]

**本项目的迁移判断：**对 `PROCESS_CREATE`、文件写入后读取、网络接收后执行分别学习或统计转移特征。常见扫描读取与真正执行链不应该共用一个传播权重。历史共现可以帮助排序，但不能新增原日志不存在的因果边；提取邻域时必须保留时间和方向。优先在现有稀有度/PPR 旁增加这种可解释特征，再决定是否需要更大的 GNN。

### GDFSL：无源头标签，不等于无传播假设

GDFSL 用观测状态与给定传播机制构造训练噪声，再通过反向过程定位源头。算法 1 明确包含传播函数 `f`，因此其“无需显式源头标签”不能扩展成“无需感染状态、传播机制或适配”。作者仓库说明当前公开入口基于 IC 模型。[^3]

**本项目的迁移判断：**从多个可疑行为时点反向寻找候选入口，再检查候选能否解释观测活动。保留多个竞争解释，避免强行选唯一根节点。正常程序执行也会创建子进程、读写文件；如果输入状态把所有活动节点当成感染节点，模型即使完成了源定位，也仍未完成攻击检测。

### VLDB Journal：严谨性应落在明确目标与上下界上

该文在 IC 模型下研究固定预算阻断和达到传播降低阈值所需的最小阻断集合。原目标存在非次模的组合效应，论文用上下界、采样和依赖数据的近似关系处理，不能把界函数上的 `1−1/e−ε` 直接宣称为原问题的统一近似比。[^4]

**本项目的迁移判断：**它最适合帮助重写我们的剪枝问题，而不是照搬删除算法。真实网络阻断是阻止传播发生；溯源图剪枝是在已经发生的日志里保留解释。建议明确“保留多少独立证据族、花费多少原始事件边”，对小图求精确最优值，再检查贪心差距。对于完整路径的 AND 条件与多条替代路径的 OR 条件，必须单独分析；当前边分数不能替代这一步。

一个简单例子：`s→a→t` 与 `s→b→t` 同时存在。单独移除 `a` 并不能切断 `t`，一起移除 `a,b` 才能切断；同样，保留半条高分路径并不等于保留完整证据。这解释了为什么逐边排名和实际路径效果可能脱节。

### PDSL：正反向联合建模很贴近目标，但训练条件尚不满足

PDSL 结合条件生成模型与 Graph Neural ODE，用候选源重建传播结果，并通过历史训练块匹配初始化推断。训练算法输入源向量与传播状态；真实社交级联实验将最早 20 个或最早 10% 参与者定义为源，并非独立取证的攻击起点。[^5]

**本项目的迁移判断：**可借鉴“反向解释应通过正向观测检查”的设计，并把不确定性暴露为多个候选源。第一步可以使用轻量的关系条件转移模型，暂不需要 ODE。只有在跨主机、跨攻击场景的训练数据足够可靠之后，才值得比较神经动力学与离散事件模型。当前固定时窗属于事后调查，若以后声称在线检测，还必须严格限制推断可见的未来事件。

## 补充检索与出版信息核验

**ICML 2026：Efficient Online Influence Maximization under the Independent Cascade Model with Node-Level Feedback。** 官方目录可核验标题，作者页列出 ICML 2026。论文 PDF 在本轮访问中被 OpenReview 验证页阻挡，因此只列为后续阅读，不据此推导算法保证。它所在的“未知传播参数与节点反馈”方向值得追踪。[^6]

**PVLDB：Augmenting Social Influence of Uncertain Seeds via Probabilistic Link Insertion。** 官方 PDF 首页记作 PVLDB 19(4), 753–766, **2025**，同时出现在 VLDB 2026 程序；应区分出版年和会议届次。已读问题定义与方法概览，尚未全面核查证明。它将种子激活、传播和新增连接的不确定性分开，适合启发 POI 先验的敏感性分析；新增连接是推荐动作，不能搬成伪造日志边。[^7]

检索还发现未来期号或仅摘要可见的源定位工作，未纳入核心推荐。本文不把“标题相关”“作者声称有效”和“已具备本项目复现条件”混为一谈。

PDF 页数、内容哈希及代码文件哈希另存于 [来源记录](social-propagation-sources.json)，不将第三方论文全文复制进仓库。

## 作者代码核查

| 项目 | 本轮实际核查 | 对复现的影响 |
|---|---|---|
| GDFSL | 固定提交 `a1be6499738a68b0eb979ae64815320c618732b3`，读取 README、`code/main_IC.py`、`code/model.py` | 训练调用 IC 模拟器；示例主循环把训练 loader 传给 `sample_and_test`，不能直接把此入口打印值当独立测试结果 [^8] |
| IMIN_BM | 固定提交 `64498b4f70b4e94b3b7b2e1159bff639a6586fc0`，读取 README、`Sandwich.cpp`、`Sandwich.h` | 输入需要带概率的图和种子集；主流程选择阻断集合并用 Monte Carlo 估计传播下降。未执行作者二进制或复核全部底层实现 [^9] |
| PDSL | 核查作者仓库 README 与文件清单 | 已有模型、训练推断和损失文件；本轮未逐行审查或训练 [^10] |
| SILN | 论文首页给出 Zenodo DOI `10.5281/zenodo.15546402` | 归档页面本轮未成功访问，不能声称已检查代码 |
| GRID | 取得作者论文 | 本轮未找到并核实对应作者实现，不用同名无关仓库替代 |

以上代码核查用于识别依赖和实验口径，不代表复现了论文结果。源头标签、感染状态、时间切分与训练图构造都需要在适配时重新检查。

## 建议的 NODOZE 方案

以下是结合当前代码的设计推断，尚待实现和实测。

### 事件层保留硬约束，传播层学习排序

建立按事件时间展开的关系图，状态包含节点 UUID、关系和生命周期。允许的转移由日志语义决定，例如进程创建、写后读、接收后执行；同一时间戳不构造先后关系。历史统计和模型训练只使用所属训练时段，不能从测试 Ground Truth 得到路标或负例。

在这些约束之上学习“给定历史和关系，下一段活动有多常见”，而不是直接把归一化 PPR 当作攻击概率。先比较小型关系条件模型与现有稀有度，再比较 GNN；新增模型应解决具体错误类型，而不是仅为加入深度学习。

### 从多个行为证据反推入口，再核查完整解释

观测路标来自检测器行为证据或人工 POI，不来自测试标签。反向寻找能连接路标的候选入口，正向重放实际日志，输出每个入口解释了哪些路标、哪些缺失，以及对应事件 ID。评分应该区分单一稀有边和有连续行为支持的路径。

候选源置信度不足时输出候选排名与缺失证据，不能用强制 top-1 掩盖歧义。传播关联节点与预测攻击节点仍然分栏；源定位、攻击节点识别、攻击路径恢复各自评价。

### 先定义证据预算问题，再讨论阈值保证

可把选择对象定义为经过核验的路径/分叉证据组，成本为各组原始事件并集的大小：

```text
选择证据组集合 S
最大化 F(S)：不同观测路标及关系证据族的覆盖收益
约束 |union(events(g) for g in S)| <= B
```

这只是明确问题的起点。共享边使组成本不是普通可加背包，完整路径又有组合要求，因此不能直接套用标准次模贪心定理。可以先在小图枚举最优集合，检查实现、输出可计算上界及实际差距，再推广采样方法。若增加阈值，其来源应是独立验证集上的误报与漏报取舍，而非在最终测试集上逐个调整到 90%。

### 分组承担计算与展示，不承担恶意标签传播

计算时对关系相似、生命周期相容的连续事件分组，关键路径事件保留独立引用。输出继续支持从组展开到原始事件。验证分组前后的路径可重放性、节点集合和证据覆盖，同时测时间与内存。只有表示近似被检查时才讨论表示误差；只有真值足够时才讨论攻击识别误差。

## 数据集准入与暂停使用

**“标注不完整”“标签冲突”“本地缺失日志”和“模型效果差”是不同问题。** 当前没有证据说明所有 OPTC 原始日志或全部 CSV 标签都错误；问题在于现有标注不足以支持想报告的完整节点/路径正确率。按保守口径，先暂停相关正式评估，并保留资料以便后续复核。[^11]

| 数据范围 | 当前处理 | 原因与允许的指标 |
|---|---|---|
| OPTC SysClient0201 的默认、30 分钟、60 分钟窗口 | 暂停正式攻击节点/路径基准；仅保留历史展示和显式诊断复算 | PDF 只直接确认两个代理，其他预测未知，缺少完整路径与负例；窗口相互重叠 |
| OPTC 攻击前背景窗口 | 暂停作为“全正常负例”基准 | 没有穷尽正常标签，不能仅凭位于攻击前就计算误报率 |
| CADETS E3 06/12/13、THEIA E3 Case 3 | 可继续做已核验 CSV 正例实体保留评估 | UUID 与本地日志匹配；仅支持已标注实体的保留率，不支持完整攻击分类或路径 F1 |
| THEIA E3 Case 1 | 暂停本轮比较 | 修正运行尚未完成，与真值是否错误无关 |
| CLEARSCOPE E3 与压缩包各 E5 场景 | 暂停 | 缺少对应本地数据库 |
| TRACE 及新加入但尚未审核的场景 | 默认不准入 | 压缩包无对应标签，或尚无来源、身份及时间范围核验 |

CADETS 13 的历史节点保留率较低，但未因此删除该场景。它仍在正例保留准入范围，避免只挑效果好的数据。CSV 正例含进程、文件和网络实体，也不能把实体保留率写成进程分类召回。[^11]

机器可读清单见 [configs/benchmark-admission.json](../configs/benchmark-admission.json)。默认 PDF 评估入口现会在读取候选日志、加载真值和调用检测器之前跳过暂停或未经审核的场景，写出 [准入执行记录](benchmark-admission.json)，保留旧实验文件。显式 `--diagnostic` 才能复算局部 PDF 标签，写到单独的 `docs/pdf-diagnostics/` 和诊断缓存目录，结果标记 `diagnostic_only`。

```bash
# 默认：执行准入检查；当前 OPTC 四个窗口都会被跳过
python webapp/scripts/evaluate_pdf_groundtruth.py

# 仅供人工复核历史局部标注，不进入正式模型排名
python webapp/scripts/evaluate_pdf_groundtruth.py --diagnostic
```

本次机制作用于上述 PDF 评估入口；既有网页和旧实验脚本仍供历史复现，未删除数据，也未把它们整体重写为新基准。后续新实验须采用准入清单，不能绕过清单继续报告暂停场景的总体正确率。

## 恢复实验时的验证顺序

先固定样本、标注范围和切分，再运行模型。训练、验证、测试按主机/攻击场景分离，并保留时间边界；同主机重叠窗口不能分别充当训练与测试。选择 POI 所使用的人工先验也要单独披露。

第一组比较保持相同候选日志、相同 POI 和相同原始边预算：当前 RASP、加入关系条件排序、加入正反向解释、再加入分组。分组数、时间衰减、阈值都在验证集选择，测试集一次冻结评估。消融必须包含无学习模块、无分组、无反向约束，以确定收益来源。

指标分成三个任务：源头定位报告排名与距离；攻击进程在完整或明确抽样设计的标签上报告 Precision/Recall/F1；路径恢复按实际事件序列核验方向、时间与完整性。只有正例时报告“已标注正例找回/保留”，不把未知当负例。另报候选生成漏失、剪枝漏失、推断漏失，以及时间、峰值内存和输出大小。

本轮没有用暂停的数据训练新传播模型或重新选优，也没有依据社交论文中的百分比推算 NODOZE 收益。可直接采用的是方法设计与复核要求；是否优于当前规则，需要在准入数据上实际比较。

## 来源

[^1]: Zihan Feng, Yajun Yang, Xin Huang, Xin Wang, Hong Gao, Qinghua Hu. **Many Hands Make Light Work: Group-based Information Diffusion Prediction over Long-Context Cascades.** WWW 2026, April 13–17. [作者 PDF](https://www.comp.hkbu.edu.hk/~xinhuang/publications/pdfs/WWW2026-Diffusion.pdf)，[DOI](https://doi.org/10.1145/3774904.3792082)。方法 §4、评估 §5、附录 B。
[^2]: Zihan Feng, Yajun Yang, Xin Huang, Hong Gao, Liping Jing, Qinghua Hu. **Efficient Sphere-Effect Based Information Diffusion Prediction on Large-scale Social Networks.** KDD 2025, August 3–7. [作者 PDF](https://yang-ya-jun.github.io/yjyang/publications/kdd25.pdf)，[DOI](https://doi.org/10.1145/3711896.3736925)。方法 §3、评估 §4。
[^3]: Dongpeng Hou, Yuchen Wang, Chao Gao, Xianghua Li. **A Generalized Diffusion Framework with Learnable Propagation Dynamics for Source Localization.** IJCAI 2025, 2919–2927. [官方页面](https://www.ijcai.org/proceedings/2025/325)，[官方 PDF](https://www.ijcai.org/proceedings/2025/0325.pdf)。§4、算法 1–2、§5。
[^4]: Jinghao Wang, Yanping Wu, Xiaoyang Wang, Ying Zhang, Lu Qin, Wenjie Zhang, Xuemin Lin. **Efficient and cost-effective influence and blocker minimization.** The VLDB Journal 35, article 53, published September 3, 2026. [出版商全文](https://link.springer.com/article/10.1007/s00778-026-01003-4)。§2–4 及实验章节；非次模性与数据相关保证分别参见定理 2、5。
[^5]: Yansong Wang, Qisen Chai, Longlong Lin, Tao Jia. **PDSL: Propagation Dynamics Aware Framework for Source Localization.** 作者版本 May 5, 2026；关联 TNSE DOI 10.1109/TNSE.2026.3688551. [arXiv 元数据](https://arxiv.org/abs/2605.03550)，[作者全文](https://arxiv.org/html/2605.03550v1)。§III、算法 1–2、§IV-A；未把未取得的 IEEE 排版版当作已读来源。
[^6]: Arpit Agarwal, Varad Deolankar, Rohan Ghuge. **Efficient Online Influence Maximization under the Independent Cascade Model with Node-Level Feedback.** [ICML 2026 官方目录](https://icml.cc/Downloads/2026)，[作者发表清单](https://agarpit.github.io/publications/)。本轮仅核验元数据。
[^7]: Xiaolong Chen, Jing Tang. **Augmenting Social Influence of Uncertain Seeds via Probabilistic Link Insertion.** PVLDB 19(4):753–766，PDF 标示 2025. [官方 PDF](https://www.vldb.org/pvldb/vol19/p753-chen.pdf)，[VLDB 2026 程序](https://vldb.org/2026/program.html)。本轮方法概览，不列入全文细读计数。
[^8]: GDFSL 作者仓库：[固定提交](https://github.com/cgao-comp/GDFSL/tree/a1be6499738a68b0eb979ae64815320c618732b3)。代码读取范围如上，不推断作者全部论文实验均使用相同示例入口。
[^9]: IMIN_BM 作者仓库：[固定提交](https://github.com/jhwang0116/IMIN_BM/tree/64498b4f70b4e94b3b7b2e1159bff639a6586fc0)。README 另列独立 IMIN 实现，本轮未审查该实现。
[^10]: PDSL 作者仓库：[README 与文件清单](https://github.com/MrYansong/PDSL)。
[^11]: 本地证据：[PDF 核验报告](pdf-groundtruth-study.md)、[上传标签逐场景审计](uploaded-groundtruth-evaluation.json)、[PDF 局部诊断结果](pdf-groundtruth-evaluation.json)。它们支持数据处置，不作为社交传播论文来源。
