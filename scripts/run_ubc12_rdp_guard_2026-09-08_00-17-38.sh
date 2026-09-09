#!/usr/bin/env bash
set -euo pipefail

cd /root/NODOZE-pruning-release

run_stamp="2026-09-08_00-17-38"
database="output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db"
annotations="output/tc/ubc-cadets-e3/pdf-stage/cadets-e3-ubc-12-annotations.json"
result="output/tc/ubc-cadets-e3/pdf-stage/cadets-e3-ubc-12-rdp-guard-${run_stamp}.json"

printf '%s\n' "$$" > "logs/cadets-e3-ubc-12-rdp-guard-${run_stamp}.pid"
printf '[%s] 启动 RDP-Guard：完整窗口、时序扩散、扩散门控稀有度、阶段路径证书\n' "$(date '+%F %T')"
python -u -m tc_pruning.cli experiment \
  --db "$database" \
  --annotations "$annotations" \
  --groundtruth-annotations "$annotations" \
  --config configs/tc_pruning_poi_alert.json \
  --output "$result"
printf '[%s] 全部完成，结果：%s\n' "$(date '+%F %T')" "$result"
