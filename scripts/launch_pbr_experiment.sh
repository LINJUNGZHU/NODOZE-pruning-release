#!/usr/bin/env bash
set -euo pipefail

config_path="${1:-configs/a_rasp_pbr_cadets_e3.json}"
output_root="${2:-output/a-rasp-pbr-runs}"
run_id="${RUN_ID:-pbr-$(date -u +%Y%m%dT%H%M%SZ)-$(python -c 'import uuid; print(uuid.uuid4().hex[:8])')}"
run_dir="${output_root}/${run_id}"

mkdir -p "${run_dir}"
log_path="${run_dir}/pipeline.log"
nohup setsid env PYTHONPATH=. python scripts/run_pbr_experiment.py \
  --config "${config_path}" --run-dir "${run_dir}" \
  >"${log_path}" 2>&1 </dev/null &
pid=$!
printf '%s\n' "${pid}" >"${run_dir}/pipeline.pid"

for _ in $(seq 1 60); do
  if ! kill -0 "${pid}" 2>/dev/null; then
    printf 'PBR process exited during startup: %s\n' "${pid}" >&2
    tail -n 40 "${log_path}" >&2 || true
    exit 1
  fi
  if [[ -s "${run_dir}/progress.json" ]]; then
    stage=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["stage"])' "${run_dir}/progress.json")
    if [[ "${stage}" != "STARTING" ]]; then
      python -c 'import json,sys; print(json.dumps({"run_id":sys.argv[1],"pid":int(sys.argv[2]),"run_dir":sys.argv[3],"log":sys.argv[4],"progress":json.load(open(sys.argv[5]))},sort_keys=True))' \
        "${run_id}" "${pid}" "$(cd "${run_dir}" && pwd)" "$(cd "$(dirname "${log_path}")" && pwd)/$(basename "${log_path}")" "${run_dir}/progress.json"
      exit 0
    fi
  fi
  sleep 1
done

printf 'PBR process is alive but did not publish progress within 60 seconds: %s\n' "${pid}" >&2
exit 1
