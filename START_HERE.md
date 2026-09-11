> Web 页面已切换为精简 OPTC 版本：`python webapp/scripts/prepare_optc.py` 准备真实窗口，
> `python webapp/backend/app.py` 启动，访问 http://127.0.0.1:8000 。
> 页面支持 Ground Truth 手动 POI、POI 前全部历史频率、剪枝对比、逐边评分及运行日志。范围和真值口径见 [webapp/README.md](webapp/README.md)。

# NODOZE 稀有度与图扩散剪枝项目

这是从原工程中提取的独立源码和数据包，用于展示和复现实验。未包含 KAIROS、DEPIMPACT 二进制工程、其他论文仓库和无关历史输出。

## 目录

- `tc_pruning/`：核心 Python 源码，包括 CDM 数据读取、SQLite 存储、NODOZE 频率模型、POI 因果搜索、DEPIMPACT-inspired 权重传播、图扩散、剪枝、连通性恢复和评价。
- `configs/tc_pruning.json`：实验参数。
- `tests/`：自动化测试。
- `output/tc/cadets-e3-v2.db`：已导入的 CADETS E3 SQLite 数据库，包含约 2182 万条事件以及离线频率统计表。
- `output/tc/frequency-models/`：UBC06、UBC12、UBC13 对应的历史频率模型快照。
- `output/tc/ubc-cadets-e3/`：三个场景的 POI、攻击节点、攻击事件和派生路径标注。
- `ubc-provenance-ground-truth-ff65bc7/darpa/E3-CADETS/`：UBC CADETS E3 原始核心节点真值文件。
- `README.md`：原项目完整说明。
- `requirements.txt`：Python 依赖。

## 环境

```powershell
conda activate graphenv
cd "NODOZE-pruning-release"
python -m pip install -r requirements.txt
```

## 运行 UBC06

数据库和 before-06 快照已经准备好，可以直接运行：

```powershell
python -m tc_pruning.cli experiment `
  --db "output\tc\cadets-e3-v2.db" `
  --annotations "output\tc\ubc-cadets-e3\cadets-e3-ubc-06-annotations.json" `
  --groundtruth-annotations "output\tc\ubc-cadets-e3\cadets-e3-ubc-06-annotations.json" `
  --output "output\tc\ubc-cadets-e3\cadets-e3-ubc-06-connectivity-results.json" `
  --config "configs\tc_pruning.json"
```

运行 UBC12 或 UBC13 时，把命令中的 `06` 分别替换成 `12` 或 `13`。

## 离线频率阶段

只有重新导入数据库后才需要执行：

```powershell
python -m tc_pruning.cli build-frequency-cache `
  --db "output\tc\cadets-e3-v2.db"

python -m tc_pruning.cli compile-ubc-frequency-snapshots `
  --db "output\tc\cadets-e3-v2.db"
```

第一条命令扫描全部原始事件，耗时较长；第二条命令生成三个可直接加载的历史模型。正常的 `experiment` 不会重新计算历史频率。

## 测试

```powershell
python -m pytest -q
```

## 真值与方法声明

UBC CSV 提供人工复核的核心攻击实体。本项目根据场景时间窗和核心实体派生攻击事件边及时间一致的 `entry -> POI` 路径，因此这些路径不是 UBC 官方逐边人工真值。数据量特征缺失时，报告会将传播方法标记为 `adapted_DEPIMPACT_without_data_flow_amount`，不会声称完整复现 DEPIMPACT。
