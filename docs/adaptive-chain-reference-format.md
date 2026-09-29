# 外部完整链参考清单

默认 CADETS 路径来自正例子图的自动派生。若已有独立审核的事件级攻击链，可以在不改算法、不重新设置评分参数的情况下接入：

```bash
python -m scripts.run_adaptive_chains \
  --output output/with-external-chain-contracts \
  --chain-references /path/to/chain-references.json --publish
```

文件格式为案例 ID 到链列表的映射。以下仅为未审核模板，不能直接当作攻击真值：

```json
{
  "cadets06": [
    {
      "id": "case06-investigation-001",
      "event_ids": ["ENTRY_EVENT_ID", "EXECUTION_EVENT_ID"],
      "branches": [
        ["ENTRY_EVENT_ID", "FILE_EVENT_ID", "EXFIL_EVENT_ID"]
      ],
      "required_event_ids": [],
      "provenance": {
        "kind": "independent_review",
        "source": "独立原始审计记录或红队报告的路径与版本"
      },
      "reviewed_by": [],
      "scope_complete": false,
      "scope": {
        "hosts": ["声明覆盖的主机"],
        "start_ns": "声明覆盖的开始纳秒",
        "end_ns": "声明覆盖的结束纳秒",
        "entry": "声明的入口",
        "outcome": "声明的最终结果"
      }
    }
  ]
}
```

每个 `event_ids` 和 `branches` 数组必须是原始日志中真实、方向一致、严格递增的有向时间序列；同刻不作为因果先后。多个分支都必需，不允许只留其中之一就计为整链成功。`required_event_ids` 可声明其它必需原始证据，不能以伪造边将无关事件串成路径。

只有实际独立复核完成之后，才应填写真实的 `reviewed_by`，并把 `scope_complete` 改成 `true`。程序还会校验所有源记录、方向和时序；它只能检查声明和证据，不能替代人的真实性审核。源记录缺失或路径无效的参考保留在分母里，但不算成功。

清单只在所有在线决策写入冻结目录并通过校验后才读取。外部必需事件即使不在原正例列表中，也会从原数据库索引查询；缺少某个案例的外部清单时，该案例回退到派生参考，并在来源中记录。`synthetic` 和 `derived_reference` 永远不会自动升级成独立审核攻击链。
