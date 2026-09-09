#!/usr/bin/env bash
set -euo pipefail

cd /root/NODOZE-pruning-release
echo $$ > logs/cadets_e3_2026-09-07_15-27-47.pid

echo "[$(date '+%F %T')] 阶段1/5：从原始 CADETS E3 JSON 导入新数据库"
python -u -m tc_pruning.cli ingest \
  --input /root/kairos-main/logs/ta1-cadets-e3-official-*.json \
  --db output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db \
  --batch-size 50000

echo "[$(date '+%F %T')] 阶段2/5：构建事件频率缓存"
python -u -m tc_pruning.cli build-frequency-cache \
  --db output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db

echo "[$(date '+%F %T')] 阶段3/5：编译场景日期之前的频率快照"
python -u -m tc_pruning.cli compile-ubc-frequency-snapshots \
  --db output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db

echo "[$(date '+%F %T')] 阶段4/5：生成独立 UBC 评价真值"
python -u -m tc_pruning.cli prepare-ubc-annotations \
  --db output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db \
  --groundtruth-dir ubc-provenance-ground-truth-ff65bc7/darpa/E3-CADETS \
  --output-dir output/tc/ubc-cadets-e3 \
  --scenario all

echo "[$(date '+%F %T')] 阶段5/5：由人工描述型关键 POI 开始搜索、扩散与剪枝"
python -u -m tc_pruning.cli experiment \
  --db output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db \
  --poi-events poi/cadets-e3-ubc-06-description-pois.json \
  --groundtruth-annotations output/tc/ubc-cadets-e3/cadets-e3-ubc-06-annotations.json \
  --output output/tc/ubc-cadets-e3/cadets-e3-ubc-06-description-poi-results-2026-09-07_15-27-47.json \
  --config configs/tc_pruning.json

echo "[$(date '+%F %T')] 全部完成"
