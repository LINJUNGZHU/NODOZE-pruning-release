# 本地参考数据准备

真实事件 ID 不随本分支发布。配置中的 `cadets-06.json`、`cadets-12.json`、`cadets-13.json` 由本机已有 CAPTAIN 标注生成，已加入 `.gitignore`。

准备本机的 `poi/cadets-e3-captain-{06,12,13}-annotations.json` 后运行：

```bash
python -m scripts.prepare_chain_references
```

也可通过 `--source-directory /path/to/local/annotations` 指定目录。脚本仅在本机读取与写入，不下载、不上传；检查三个文件的标注来源与场景一致后，提取 `attack_event_ids` 和 `metadata`。已有相同内容可重复运行，冲突文件会拒绝覆盖。

这些是事件正例，不能作为独立审核过的完整攻击链。完整链审核格式见[参考合同](../../docs/adaptive-chain-reference-format.md)。真实实验还需要 `configs/adaptive_chain_study.json` 指定的本机数据库及候选账本。合成实验使用 `python -m scripts.run_adaptive_chains --synthetic-only --output output/new-synthetic-run`，不依赖这些文件。
