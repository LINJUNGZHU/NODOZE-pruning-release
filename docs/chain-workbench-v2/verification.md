# 工作台与实际保留导出的验收

本轮 `20260930-r1` 已完成实际验收，机器可读记录见 [validation.json](validation.json)，聚合及图表哈希见 [aggregate-audit.json](aggregate-audit.json)。

- 干净源码快照：1078项测试通过、2项跳过。
- 9个案例、36个变体、2520个冻结决策全部校验；CSV逐行与JSON一致。
- 实际Flask服务：24份导出、72个三格式下载、15份参考叠加核对通过；工作台核对504个首末预算点及15个精确导出链接。
- Chromium无浏览器错误；390px布局、纳秒时间、完整/断裂筛选、错配拒绝与异步切换通过。
- 公开聚合与84张图未命中880个本机参考/POI真实ID；明细与截图保留本机。

以下命令从项目根目录运行。浏览器检查使用 Playwright Chromium；输出截图及 `verification.json`。合成 fixture 仅验证界面行为，不发布为实验成绩。

## 导出与不可变来源

```bash
python -m pytest -q tests/test_export_chain_workbench.py tests/test_retained_chains.py tests/test_chain_workbench_freeze_validation.py
python -m scripts.export_chain_workbench --frozen <冻结变体目录> --method reliability_chain --budget 1024 --output <不存在的新目录>
```

v2 的预算是候选事件条目整数；候选中的 LINEAGE 派生关系也占预算，不应全部称为独立原始审计事件。导出先调用严格冻结验证，再读取 `method@budget` 的既有掩码与该方法的原始评分；不重跑扩散或选择，不读取离线标签。来源摘要与完整 manifest 的 SHA-256 随本机导出保存。缺失的方法、未冻结预算、浮点预算、源文件篡改、覆盖已有输出均应拒绝。

CSV / GraphML / JSON 表达同一保留事件并集。严格时序路径是一种覆盖分解，含全部单事件路径，不是所有可能路径的枚举，也不是攻击数量。观测见证单独保存，其候选范围内完整性不等于独立攻击范围完整性。

`poi_roles` 分开记录原始输入 POI、当前所用起点和算法建议。原始输入 POI 可能在某策略中未被用作起点；算法建议也可能重新选中原始输入。界面保留这种重叠，不把任何建议自动标为已核验告警。

## 合成界面回归

```bash
python webapp/scripts/verify_research_workbench.py --output /tmp/nodoze-workbench-fixture
python webapp/scripts/verify_retained_chains.py --output /tmp/nodoze-retained-fixture
```

覆盖实际保留事件分页并集、纳秒字符串、EXECUTE 因果方向、共享实体分支、单事件、起点角色、候选条目预算匹配、零分母 N/A、部分标注范围、E5 仅有标注、安全文本、键盘操作、390px 布局及缺文件提示。

## 已生成文件的界面合约

```bash
python webapp/scripts/verify_research_workbench.py --report <汇总JSON> --output /tmp/nodoze-workbench-report
python webapp/scripts/verify_retained_chains.py --catalog webapp/frontend/retained-chain-catalog.json --output /tmp/nodoze-retained-catalog
```

未给 `--base-url` 时，脚本启动本地静态测试服务。`--report` 将指定汇总提供给页面，核对各案例、范围、起点策略和方法的首末预算；这验证文件与界面合约，不代表真实 Flask 路由已验收。`--catalog` 仍通过 HTTP 读取目录链接的实际文件，并读完三格式下载内容。

单个本机导出的快速合约检查可用 `--artifact <retained-graph.json>`；此选项会注入该文件供界面检查，不代表其公开下载路径已经发布。

## 实际运行服务

```bash
python webapp/scripts/verify_research_workbench.py --base-url http://127.0.0.1:8000 --report webapp/frontend/chain-workbench-summary.json --output /tmp/nodoze-workbench-live
python webapp/scripts/verify_retained_chains.py --base-url http://127.0.0.1:8000 --catalog webapp/frontend/retained-chain-catalog.json --output /tmp/nodoze-retained-live
```

实际服务阶段先核对 HTTP 返回的汇总 / 目录与预期文件一致，再取消相应 fixture 拦截，让页面直接读取服务响应。随后核对聚合计数、角色、精确事件时间和真实下载。若服务仍提供旧文件，应失败而不是用本地新报告掩盖部署不同步。

详细事件、角色列表和本地目录不得混入公开聚合汇总。界面检查通过也不证明检测准确率或完整攻击真值；这些结论仍依赖冻结协议与离线评价依据。

## 固定参考核对面板

目录条目的可选 `reference_audit_url` 指向本机 `reference-audit.json`。它是全部冻结完成后的离线标注层，与保留导出分开生成；不是选择器输入。页面要求来源 manifest 哈希、案例、范围、POI 策略、方法和整数预算全部匹配。

验收还覆盖完整 / 断裂筛选、缺失事件与精确时间、来源和决策错配拒绝、畸形时间字段拒绝、目录切换时丢弃旧请求、390px布局。坏的参考文件只关闭参考核对，实际保留子图仍可查看。离线身份使用大小写规范化匹配，显示保留文件原文，不据此改写冻结事件。

参考覆盖正事件数、未形成多事件参考的单例数与 LINEAGE 派生关系占比必须同时可见。尤其当全部参考含 LINEAGE 时，100%固定参考保留不能解释为全部正事件或独立原始日志的完整攻击链保留。未标注案例显示 N/A。

## 曲线点与保留图的精确对应

工作台读取本机导出目录，仅在案例、候选范围、POI 策略、方法、整数预算全部匹配时提供该点的直达链接。保留图页面支持 `?entry=<目录ID>`；未知 ID 明确失败，不以目录首项替代。没有对应图时仍可查看汇总曲线，并用 `scripts.export_chain_workbench` 精确导出已有冻结决策。

本轮提供 15 份 `reliability_chain / 1024` 代表导出；目录另分组保留旧版 9 份归档。它们不能代表全部 2520 个决策的任意点。浏览器回归逐项改变五个匹配条件，验证不会出现错误跳转，并验证指定 ID 与未知 ID 行为。
