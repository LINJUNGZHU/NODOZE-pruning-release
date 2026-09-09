#!/usr/bin/env bash
set -uo pipefail

run_id="${1:-$(date '+%Y-%m-%d_%H-%M-%S')}"
project_dir="/root/NODOZE-pruning-release"
output_dir="${project_dir}/output/tc/poi-prefix-sweep/${run_id}"
status_file="${output_dir}/process-status.json"

if [ -e "${output_dir}" ]; then
  echo "refusing to overwrite existing run directory: ${output_dir}" >&2
  exit 2
fi
mkdir -p "${output_dir}"
printf '%s\n' "$$" > "${output_dir}/pid"
printf '{"status":"running","run_id":"%s","pid":%s}\n' \
  "${run_id}" "$$" > "${status_file}"

cd "${project_dir}" || exit 1
python -u -m tc_pruning.cli poi-prefix-experiment \
  --db output/tc/cadets-e3-from-raw-2026-09-07_15-27-47.db \
  --spec configs/cadets_e3_poi_prefix_sweep.json \
  --config configs/tc_pruning_poi_alert.json \
  --output-dir "${output_dir}"
exit_code=$?

if [ "${exit_code}" -eq 0 ]; then
  # The independent validator requires a completed producer state.  Mark it
  # provisionally complete, then fail the overall job if deep validation does
  # not independently reproduce every certificate and ledger invariant.
  printf '{"status":"complete","validation_status":"pending","run_id":"%s","pid":%s,"exit_code":0}\n' \
    "${run_id}" "$$" > "${status_file}"
  python -u scripts/validate_ps_rdp_sweep.py "${output_dir}"
  exit_code=$?
fi
if [ "${exit_code}" -eq 0 ]; then
  status="complete"
  validation_status="passed"
else
  status="failed"
  validation_status="failed"
fi
printf '{"status":"%s","validation_status":"%s","run_id":"%s","pid":%s,"exit_code":%s}\n' \
  "${status}" "${validation_status}" "${run_id}" "$$" "${exit_code}" > "${status_file}"
exit "${exit_code}"
