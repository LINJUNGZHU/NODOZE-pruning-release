# V8 RRF 修订：一次限定的开发集后续实验

第一轮冻结选择版本 aabf675 完成后，独立评测发现候选严重丢失：五案 V8 物化池的已知正例只有 8/6/12/11/8，V7 对应 38/14/14/229/29；原始主预算 V8 宏覆盖率 13.98%，原完整账本强基线 76.96%。该负结果完整保留。

据此只修改**候选组描述符排序**：复用 V7 已有的三视图 RRF（频率扩散主视图、原历史稀有度视图、POI 时间/路径视图，c=60）。保留 V8 的几何展开、真实事件并集容量、原评分、合法时间证书、η=1 和精确跨组目标。权重不来自标注，不添加案例文件/IP/ID 规则。

代码：group_completion_rrf.py 为原 GroupIndex 包装固定排序，所有成员/分数/偏移仍由原组索引提供。运行器不读取标签，生成后独立评测。两方法：相同候选池的 edge 和 concave；B=64/256/1024/4096。五案质量 40 项，五次独立进程资源重复。没有为每个案例挑参数，也不扫描新的参数网格。

这是观察已用开发案例后提出的修订，不是未见确认实验。无论结果好坏都保存，不把两轮最高单元格拼成一个方法。本次到此结束调参；产品默认保持已验收版本。

```bash
PYTHONPATH=. python scripts/run_group_completion_matrix_v8.py --runner scripts/run_group_completion_rrf_v8.py --workers 5 --data-root /path/to/data --output /path/to/v8-rrf
PYTHONPATH=. python scripts/evaluate_group_completion_v8.py --config configs/group_completion_v8_rrf.json --input /path/to/v8-rrf/quality --profiles /path/to/v8-rrf/profiles --output docs/group-completion-v8/rrf-results.json
```
