#!/usr/bin/env bash
set -euo pipefail

cd /root/NODOZE-pruning-release
echo $$ > logs/ubc12_pdf_pois_2026-09-07_21-09-53.pid

echo "[$(date '+%F %T')] 从新 darpa CSV 生成 UBC12 独立评价真值"
python -u -m tc_pruning.cli prepare-ubc-annotations \
  --db output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db \
  --groundtruth-dir darpa/E3-CADETS \
  --output-dir output/tc/ubc-cadets-e3/pdf-reselected \
  --scenario 12

echo "[$(date '+%F %T')] 使用 PDF 重新选择的 3 个 POI 运行搜索、扩散和剪枝"
python -u -m tc_pruning.cli experiment \
  --db output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db \
  --poi-events poi/cadets-e3-ubc-12-pdf-reselected-pois.json \
  --groundtruth-annotations output/tc/ubc-cadets-e3/pdf-reselected/cadets-e3-ubc-12-annotations.json \
  --output output/tc/ubc-cadets-e3/pdf-reselected/cadets-e3-ubc-12-pdf-poi-results-2026-09-07_21-09-53.json \
  --config configs/tc_pruning.json

echo "[$(date '+%F %T')] 全部完成"
