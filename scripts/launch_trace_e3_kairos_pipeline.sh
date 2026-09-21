#!/usr/bin/env bash
set -Eeuo pipefail

REPO_ROOT=/root/NODOZE-pruning-release/.worktrees/query-adaptive-cadets-e3
RUN_ROOT=${REPO_ROOT}/output/trace-e3-kairos-poi-runs
RUN_ID=trace-e3-kairos-poi-$(date +%Y%m%d-%H%M%S)
RUN_DIR=${RUN_ROOT}/${RUN_ID}
mkdir -p "${RUN_DIR}"
nohup setsid bash "${REPO_ROOT}/scripts/run_trace_e3_kairos_pipeline.sh" "${RUN_DIR}" \
  >"${RUN_DIR}/pipeline.log" 2>&1 < /dev/null &
PIPELINE_PID=$!
python - "${RUN_DIR}/launch.json" "${RUN_ID}" "${PIPELINE_PID}" <<'PY'
import json, os, pathlib, sys, time
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({"run_id": sys.argv[2], "pid": int(sys.argv[3]),
                            "launched_ns": time.time_ns()}, indent=2) + "\n")
PY
python - "${RUN_DIR}/pipeline.pid" "${PIPELINE_PID}" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_text(sys.argv[2] + "\n")
PY
ln -sfn "${RUN_DIR}" "${RUN_ROOT}/latest"
printf '%s\n' "${RUN_DIR}"
