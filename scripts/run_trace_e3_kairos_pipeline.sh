#!/usr/bin/env bash
set -Eeuo pipefail

REPO_ROOT=/root/NODOZE-pruning-release/.worktrees/query-adaptive-cadets-e3
PIDSM_ROOT=/root/PIDSMaker-main
PIDSM_PYTHON=/opt/conda/envs/pidsmaker39/bin/python
RUN_DIR=${1:?run directory is required}
ARTIFACT_DIR=/root/pidsmaker-artifacts-trace-e3-kairos-localday-v2
SQLITE_DB=/root/NODOZE-pruning-release/output/tc/trace-e3-from-tapas-2026-09-09_14-53-07.db
DETECTOR_DIR=${RUN_DIR}/detector
OFFLINE_DIR=${RUN_DIR}/offline
STATUS_PATH=${RUN_DIR}/process-status.json

mkdir -p "${RUN_DIR}" "${DETECTOR_DIR}" "${OFFLINE_DIR}"

write_status() {
  local status_value=$1
  local stage_value=$2
  local detail_value=${3:-}
  python - "${STATUS_PATH}" "${status_value}" "${stage_value}" "${detail_value}" <<'PY'
import json, os, pathlib, sys, time
path = pathlib.Path(sys.argv[1])
value = {"status": sys.argv[2], "stage": sys.argv[3], "detail": sys.argv[4],
         "pid": os.getppid(), "updated_ns": time.time_ns()}
temporary = path.with_suffix(".tmp")
temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
os.replace(temporary, path)
PY
}

fail_pipeline() {
  local code=$?
  trap - ERR
  write_status FAILED "${CURRENT_STAGE:-UNKNOWN}" "exit=${code}"
  exit "${code}"
}
trap 'fail_pipeline' ERR

CURRENT_STAGE=BUILD_TRACE_POSTGRES_FROM_LOCAL_SQLITE
write_status RUNNING "${CURRENT_STAGE}"
[[ -s "${SQLITE_DB}" ]]
cd "${REPO_ROOT}"
PYTHONPATH="${REPO_ROOT}" python scripts/build_trace_e3_postgres.py \
  --sqlite "${SQLITE_DB}" --status "${RUN_DIR}/postgres-import-status.json" \
  --host 127.0.0.1 --user postgres --password postgres --database trace_e3
export PGPASSWORD=postgres
for required_table in event_table subject_node_table file_node_table netflow_node_table; do
  psql -h 127.0.0.1 -U postgres -d trace_e3 -Atc \
    "SELECT to_regclass('public.${required_table}') IS NOT NULL" | grep -qx t
done

CURRENT_STAGE=TRAIN_KAIROS
write_status RUNNING "${CURRENT_STAGE}"
TRACE_E3_LOCAL_SINGLE_DAY=1 PIDSMaker_ROOT="${PIDSM_ROOT}" PYTHONPATH="${PIDSM_ROOT}:${REPO_ROOT}" \
  "${PIDSM_PYTHON}" scripts/run_trace_kairos_training.py kairos TRACE_E3 \
  --database_host=127.0.0.1 --database_port=5432 \
  --database_user=postgres --database_password=postgres \
  --artifact_dir="${ARTIFACT_DIR}" \
  --training.decoder.use_few_shot=False \
  --training.ocrapt_early_stop.enabled=False

CURRENT_STAGE=FREEZE_KAIROS_POIS
write_status RUNNING "${CURRENT_STAGE}"
PYTHONPATH="${REPO_ROOT}" python scripts/freeze_trace_kairos_pois.py \
  --training-status "${ARTIFACT_DIR}/trace-e3-kairos-training-status.json" \
  --output-dir "${DETECTOR_DIR}" --database-host 127.0.0.1 \
  --database-user postgres --database-password postgres --database-name trace_e3

CURRENT_STAGE=PRUNE_AND_OFFLINE_ORTHRUS
write_status RUNNING "${CURRENT_STAGE}"
PYTHONPATH="${REPO_ROOT}" python scripts/run_trace_kairos_poi_experiment.py \
  --db "${SQLITE_DB}" \
  --poi-seal "${DETECTOR_DIR}/kairos-poi-seal.json" \
  --queue-manifest "${DETECTOR_DIR}/native-queues.json" \
  --groundtruth "${PIDSM_ROOT}/Ground_Truth/orthrus/E3-TRACE/node_trace_e3_firefox_0410.csv" \
  --groundtruth "${PIDSM_ROOT}/Ground_Truth/orthrus/E3-TRACE/node_trace_e3_phishing_executable_0413.csv" \
  --groundtruth "${PIDSM_ROOT}/Ground_Truth/orthrus/E3-TRACE/node_trace_e3_pine_0413.csv" \
  --run-dir "${OFFLINE_DIR}" \
  --candidate-cap 20000 \
  --selection-cap 12000

CURRENT_STAGE=COMPLETED
write_status COMPLETED "${CURRENT_STAGE}" "${OFFLINE_DIR}/evaluation.json"
