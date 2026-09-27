# V8 展开准入修正：保留前两轮，单独验证

r3 单主视图候选和 r4 三视图 RRF 候选都发生严重正例物化丢失。r4 已执行的质量输出显示仅换排序没有改善最终覆盖。本次不新增评分规则和参数网格，而是修正展开阶段的职责：

- 代表探索达到已有四分之一容量限制时停止；小图如容量允许，至少给强制事件之外一条探索机会。
- 继续/完整组展开仅作用于**代表已准入**的组。原循环在该阶段还会给新描述符创建代表，把剩余容量再次用作广泛探索。
- 最后再按原顺序用剩余容量补代表；事件和完整时间证书仍按真实并集计费。

r3/r4 模块、配置与输出不改写。新模块 group_completion_expansion.py、新配置 group_completion_v8_expansion.json；原频率/扩散评分、三视图 RRF c=60、组跨度 10 秒、η=1、选择器与 cap32768/max_examined327680 全部复用。

两方法共享新候选：v8_expansion_edge 与 v8_expansion_concave。B=64/256/1024/4096，五开发案，共 40 项质量决策；再做 25 个新进程资源重复。独立评测仍使用相同部分正例，官方等价 FP/FN/P/R/F1 为 NA。

这是事后诊断后的实现修订，不能包装成预注册或未见测试，也不能因它更符合设计就声称召回提高。前三轮均发布，无收益时保留失败，不继续搜索单案规则。

```bash
PYTHONPATH=. python scripts/run_group_completion_matrix_v8.py --runner scripts/run_group_completion_expansion_v8.py --workers 5 --data-root /path/to/data --output /path/to/v8-expansion
PYTHONPATH=. python scripts/evaluate_group_completion_v8.py --config configs/group_completion_v8_expansion.json --input /path/to/v8-expansion/quality --output /path/to/v8-expansion/quality-evaluation.json
```

最终报告分别列候选闭包正例覆盖、预算内正例覆盖、排除 POI 覆盖、参考组完整性和资源。组目标与单边目标共享池；旧 V7 对比仍包含表示/准入差异，不能归因于一个模块。旧六方法与新两方法的整轮 RSS/用时工作量不同，不作直接速度胜负比较。
