#!/usr/bin/env bash
set -euo pipefail

cd /root/NODOZE-pruning-release
RUN_STAMP="${RUN_STAMP:-2026-09-07_22-46-04}"
DB="output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db"
POIS="poi/cadets-e3-ubc-12-pdf-stage-pois.json"
ANNOTATION_DIR="output/tc/ubc-cadets-e3/pdf-stage"
ANNOTATIONS="${ANNOTATION_DIR}/cadets-e3-ubc-12-annotations.json"
RESULT="${ANNOTATION_DIR}/cadets-e3-ubc-12-poi-alert-results-${RUN_STAMP}.json"

echo "$$" > "logs/ubc12_poi_alert_${RUN_STAMP}.pid"
echo "[$(date '+%F %T')] 生成基于 DARPA PDF 有序 POI 的 UBC-12 标注"
python -u -m tc_pruning.cli prepare-ubc-annotations \
  --db "$DB" \
  --groundtruth-dir darpa/E3-CADETS \
  --output-dir "$ANNOTATION_DIR" \
  --scenario 12 \
  --poi-events "$POIS"

echo "[$(date '+%F %T')] 启动完整窗口、时序扩散和攻击阶段骨架保护实验"
python -u -m tc_pruning.cli experiment \
  --db "$DB" \
  --annotations "$ANNOTATIONS" \
  --groundtruth-annotations "$ANNOTATIONS" \
  --output "$RESULT" \
  --config configs/tc_pruning_poi_alert.json

echo "[$(date '+%F %T')] 全部完成，结果：$RESULT"
