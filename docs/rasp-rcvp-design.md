# RASP-RCVP 实施设计记录

状态：已按用户“直接实现”指令实施。此文保留设计依据；最终数学定义和范围以 [实现说明](rasp-rcvp-method.md) 为准，结果见 [评估报告](rasp-rcvp-report.md)。

## 已核实的项目状态

- 主仓库 `/root/NODOZE-pruning-release`，origin 为 `git@github.com:LINJUNGZHU/NODOZE-pruning-release.git`，检查时 HEAD 为 `babd6ed`。
- 基线：在项目目录执行 `PYTHONPATH=. python -m pytest -q`，结果 **457 passed in 9.50s**。覆盖 `tests` 和 `webapp/tests`。
- 已有未提交工作：`webapp/scripts/prepare_demo.py`，以及网页展示修复文档、两个脚本和一个测试文件。实施时不得覆盖或混入提交。
- 网页是 Flask + 原生 HTML/CSS/JS；`optc_investigation.rescore` 调用 `rasp.propagate`，再调用 evidence/context 证据组选择。
- CLI 有独立的 `diffusion.diffuse_importance`、`pruning.adaptive_prune` 和版本化 score ledger。不能仅更改 `rasp.py` 就声称 CLI 已支持新算法。
- `social_propagation.py` 已有关系内部归一化、严格 timestamp 批处理和反向/分叉见证。新模块优先复用这些概念及接口，补充背景对比和根核验。
- 现有 `time_respecting_bidir` 实现逐事件发布传播状态；新模式必须改用整组同 timestamp 读取完成后统一发布，避免同 timestamp 的 event ID 排序产生虚假因果。

## 方案选择

采用共享 RCVP 算法内核，分别适配 CLI 图对象与网页数组输入。保留旧流程、默认配置、候选构造和原始事件身份。

仅扩展离线社交实验无法满足网页和 CLI 的交付要求；分别复制两套传播实现会造成时序和审计语义漂移，因此不采用。

## A：关系与时间传播

集中配置 relation family 映射，复用输入解析器的规范化信息流方向，unknown 进入 `other`。方向解释不写入 family 判断。

在合法 temporal state 的出边中，先按 family 内的交互权重归一化，再按当前有合法邻居的 family 权重混合：

`P(e | s) = omega[r] / sum_active(omega) * w(e,s) / sum_family(w)`。

`w(e,s)` 包括现有交互权重及可选 `exp(-delta_t / tau_r)`。时间差由传播状态到事件的真实时间计算；全局 tau 支持 family override，不叠加第二套旧时间衰减。

fanout 修正复用时间片统计。对一个源的所有出边都乘相同系数再归一化会完全抵消，因此修正作为状态发出的传播质量衰减，并在 ledger 明确报告其位置。

POI 与 background 共用算子和时间支持范围，仅 seed distribution 不同。background 是图结构参考分布，不是经过正常标签训练的模型。支持 legacy、uniform family mixing、configured family mixing。

`lift = log1p(max(p_poi / max(p_bg, eps) - 1, 0))`，数值保护和迭代诊断与项目契约一致；若采用有限时序 DAG 求值，应明确记录 exact temporal evaluation，不能伪称 PPR 收敛。

## B：反向定位与正向核验

POI 反向传播保存 immutable temporal witness。候选根必须具有正 backward support、严格合法到 POI 的 witness；优先 process-like UUID，按最低分、分位数和数量上限过滤，同一实体不重复。

根 seed 包含 UUID、合法起始时间和按 backward score 归一化的质量，不能丢掉时间后只按节点重新传播。通过相同正向算子产生 root-forward support。

`roundtrip = 2 * backward * root_forward / (backward + root_forward)`，零分母为零。只用 harmonic mean 核验 upstream channel；POI-forward downstream 与 terminal consequence 单列。

各 channel 记录归一化前值、分母和归一化后值。`D = 1 - product(1 - lambda_c * S_c)`；D 接入现有 RDP-Guard，rarity/path/impact/behavior 定义保留。legacy diffusion 单独保留作消融和审计。

## C：渐进剪枝

在 `adaptive_prune` 的既有 atomic group、mandatory core、mandatory bridge 与 path-cover 规划后接入实验分支。网页通过适配器复用同一预算和守卫逻辑，不以展示聚合组数量计费。

从完整 eligible groups 开始，按每组价值的 lazy heap 逐步删除。价值包含已有融合分、verification 支持与弱 redundancy 正则；正则单独消融。维护 group membership、witness 依赖与引用计数，局部失效只更新受影响队列项，不逐边执行全图传播。

删除前核验 POI/alert、certificate/path-cover、声明桥、temporal witness 和 prefix overlap。对保留依赖仍被使用的 group 拒绝删除并记录原因；固定 witness 的保守性必须在负结果中说明。最低成本超过预算继续报告不可行及真实 overflow，不能声称达到预算。

前缀使用已有 immutable POI-local scoring/noisy-OR 契约；根选择在 POI-local 范围确定，不能随着后续 POI 加入重写已冻结局部分数。

## 网页改动

- 原页面增加算法预设：当前默认、relation-aware、full RASP-RCVP；传播和剪枝选择可用于消融。
- 保留 5%、10%、20%、30% raw-event budget，显示请求预算、实际保留数、预算可行性、证书状态及运行时间。
- 事件详情增加 relation/time/fanout、POI/background 正反向得分、根核验、融合分以及逐轮删除审计；相关性不能显示成恶意概率。
- 后端检查配置枚举、有限数值与范围；缓存键绑定算法配置、候选身份与 POI，避免旧结果错配新选项。
- 新模式的前后图、逐边分数、保留标记和报告来自同一次冻结输出。OPTC 继续标记开发诊断范围。

## 文件边界

预计新增 RCVP 配置/关系内核、传播模块、渐进剪枝模块、实验 runner、测试和方法/实验报告；具体命名跟随实现阶段接口核查。

集成点：`tc_pruning/config.py`、`diffusion.py`、`pruning.py`、CLI 实验编排与 prefix 参数/哈希传递、`score_ledger.py`、`optc_investigation.py`，以及 `webapp/backend/app.py`、`frontend/index.html`、`app.js`、`styles.css`。

旧 ledger 字段保留，新增显式 RCVP schema/version 及对应深度 validator。实现、配置、候选、根候选、评分和决策均绑定 manifest hash。

## 配置与实验冻结

提供 conservative、relation-aware、full 三个实验 preset；现有默认文件不切换。参数只按数值稳定性和明确记录的开发依据制定，不以测试真值调参。

冻结 A–G：当前方法、关系传播、加 time/fanout、加 backward、加 forward verification、当前传播配 progressive、full；每种 5/10/20/30%。H/I 在资源允许时加入。对当前 RASP 与 RDP-Guard 的不同生产入口分别标记，不能把旧分数 Top-K 冒充完整 RDP-Guard。

当前 benchmark-admission 只允许 THEIA Case 3 和 CADETS 06/12/13 的正例实体保留评估，尚无 complete attack-node/path classification 准入场景。报告将：

- 分开 candidate coverage、conditional retention 和 end-to-end recall，保存分子/分母。
- 报告 raw event/node compression、派生参考事件和路径保留、严格可达与在线证书。
- 对独立人工完整攻击路径指标记 N/A，解释标签缺失；不使用未知节点构造负例 precision/F1。
- 每场景/方法记录 wall time、分阶段耗时、采样 peak RSS、ledger validator、prefix monotonicity/churn。
- 明确四场景已有开发使用历史；不宣称独立 held-out 泛化证据。

## 验收和提交

实现用户要求的十二类 deterministic toy tests，另含输入顺序重排、相同 timestamp、空根集合、非法配置、重叠 atomic expansion、旧 ledger 兼容与网页 API/结果联动。

执行顺序：全量 pytest → ledger validator → toy tests → 小场景 smoke → baseline/传播消融/剪枝消融 → 多预算 → 多场景汇总 → Markdown 报告。若出现回归，定位并记录，不能隐藏。

检查 profiling 的状态数、邻接访问次数和 heap 更新次数；发现明显二次复杂度先修复再跑大场景。运行产物使用新目录，原始数据库和大体积 ledger 不提交 Git。

GitHub 上传已由用户明确授权。实施完成后只提交本次源码、配置、测试、报告，核验 staged diff、测试和 commit 后推送，并核对远端 commit。当前既有未提交网页修复不擅自纳入。

默认升级要求跨场景、多预算稳定收益；任何不稳定模块保持实验状态，报告低预算退步、开销和不可行点。交付报告逐项回答用户要求的十个研究问题，不预先承诺正结果。
