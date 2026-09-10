# RASP-D：多样性选边实验（2026-09-10）

这是 RASP 的**实验分支**，不是全面优于 RASP 的替代品。网页默认仍为 RASP。
稀有度、背景对照 PPR、时序共同原因分叉全部沿用 RASP，仅改变预算内的选边顺序。

## 论文启发及适配边界

- [Submodular meets Structured，NeurIPS 2014](https://proceedings.neurips.cc/paper_files/paper/2014/hash/8fcd0c8d0e4335895172454b51bcc506-Abstract.html)：质量项与多样性项结合，避免高分重复项目占满摘要。这里将项目改成事件，将类别改成有向源—目标—关系交互族。
- [Submodular Optimization with Submodular Cover and Submodular Knapsack Constraints，NeurIPS 2013](https://proceedings.neurips.cc/paper/2013/hash/a1d50185e7426cbb0acad1e6ca74b9aa-Abstract.html)：覆盖收益和成本应区分。这里一个锚点需要整组因果连接，已保留的连接可共享，不按锚点数冒充边成本。
- [Core-sets for Fair and Diverse Data Summarization，NeurIPS 2023](https://proceedings.neurips.cc/paper_files/paper/2023/hash/f980ba94f513168f2b292f58aef929ec-Abstract-Conference.html)：摘要应考虑代表性。本文是度量空间公平摘要，不能直接把它的保证或加速比移植到溯源事件。
- [Robust Graph Representation Learning via Neural Sparsification，ICML 2020](https://proceedings.mlr.press/v119/zheng20d.html)：任务驱动稀疏化值得研究，但当前没有独立的训练/验证/测试划分，因此本轮没有用攻击真值训练神经网络再在同一攻击上汇报泛化效果。
- [Graph fission and cross-validation，AISTATS 2024](https://proceedings.mlr.press/v238/leiner24a.html)：图数据验证需要处理依赖性。本文的分布假设并未在本项目验证，不将同一攻击的随机分边声称为独立测试。

## 固定评分与动态选择分离

固定事件重要性为 RASP 的 `s_e >= 0`，不是校准的恶意概率。
交互族 `g=(src,dst,relation)`，权重 `w_g=max(s_e)`，已选质量 `m_g=sum(s_e)`。

目标函数为：

`F(S) = q Σ[e∈S] s_e + (1-q) Σ[g] w_g log(1 + m_g(S)/w_g)`。

权重为零的族贡献为零。第一项保留质量偏好，第二项对重复交互边际收益递减。
固定 `s,w` 后此集合函数单调且子模；**实现并非完整求解这个目标**：它按候选锚点的边际收益排序，再整体接纳其时序分叉连接。连接边也更新族质量。
重叠连接组、预算不可行锚点的跳过、未计算整组边际收益，使经典基数约束贪心的 `1-1/e` 保证不适用。
已跳过的超预算锚点不会因后续共享连接而重新考虑，这也是启发式限制。

每族维护一个最高固定分候选，用惰性堆重新核算边际收益。族质量只增不减，旧收益是上界。
没有除以动态新增连接成本，因为共享连接会降低成本，破坏惰性上界。
POI 与所有连接均计入原始事件边硬预算；选边不读真值、实体名称或旧算法决策。

## 同预算实测：收益与失败都保留

四个开发案例各运行 16 组：预算 1%、5%、10%、20%，原 RASP 与 q=0、0.05、0.25。
运行前指定主参数 q=0.05，没有按案例挑选最优权重。下表是**攻击事件召回**，不是完整攻击路径召回。

|案例|20% 原 RASP|20% RASP-D|1% 原 RASP|1% RASP-D|
|---|---:|---:|---:|---:|
|THEIA Case 3|98.85%|99.54%|34.25%|4.02%|
|CADETS-06|100%|100%|98.88%|100%|
|CADETS-12|99.12%|99.16%|15.34%|1.26%|
|CADETS-13|82.73%|84.34%|69.28%|20.28%|

20% 时参考短链分别为 3/3、3/3、8/8、3/3，两方法相同。
THEIA 5% 时交互族覆盖从 19.66% 提升到 77.53%，但事件召回从 34.25% 降到 20.69%：这是不同指标的真实冲突，不能包装成全面改善。
CADETS-13 1% 时短链从 1/3 到 3/3，却损失大量重复攻击事件，再次说明短参考链完整不代表攻击完整。
q=0 在 THEIA 20% 达到 100%，但 CADETS-06 1% 只有 71.64%，不能挑出一个最佳点称为统一结果。

原因：重复行为既可能是常态噪声，也可能是实际攻击的反复读写；无标签的多样性偏好无法区分二者。
本轮结论是增加一种有解释的预算选择机制，**没有解决低预算攻击召回问题，也未证明顶会水平**。
更进一步应在独立攻击验证上研究时间分段的行为覆盖与原始事件保真之间的约束，而非继续根据这四例调权重。

## 复现与逐边审计

```bash
cd /root/NODOZE-pruning-release
run_id=$(date '+%Y-%m-%d_%H-%M-%S')
setsid -f python -u -m scripts.run_rasp_diverse \
  --ledger output/tc/theia-case3-poi-prefix-fixed-2026-09-09_23-36-33/scenario-theia-case3/poi-prefix-3-ledger/edge-scores.jsonl.gz \
  --reference output/tc/theia-case3-poi-prefix-fixed-2026-09-09_23-36-33/scenario-theia-case3/fixed-reference.json \
  --output "output/tc/rasp-diverse-theia-${run_id}" \
  > "logs/rasp-diverse-theia-${run_id}.log" 2>&1 < /dev/null
```

三天的源目录与 POI 前缀见 `configs/rasp_cadets_validation.json`；替换上述 ledger/reference/output 即可，用同一配置运行。
本轮日志和输出时间戳为 `2026-09-10_13-44-47`。
`comparison.json` 保存全部指标、配置、代码与选边输入哈希；`diverse-decisions.jsonl.gz` 保存每条事件的固定分数、族编号、所有预算决策以及主配置入选次序和锚点边际收益。
非锚点边际收益为 null，并不表示重要性为零。主配置原因不能用来解释其他预算；网页仅在对应配置展示它。
所有选边掩码冻结后才读取攻击标签。64 组均未超预算，保留事件未丢失其原有可达 POI 分叉连接；这不保证未选攻击被保留。
运行时间是已有候选账本的传播、选择与审计时间，不包含原始 CDM 导入，不能与论文端到端耗时直接比较。
POI 来自既有报告辅助调查，四个案例都是开发集。网页三天展示指标，图仍是 THEIA 固定抽样；数据和运行产物不上传 GitHub。
