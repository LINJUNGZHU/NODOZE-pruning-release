#!/usr/bin/env bash
# Re-run the row-order-corrected first-stage protocol in two NEW directories.
set -euo pipefail
cd /root/NODOZE-pruning-release/.worktrees/sparse-five-case-study
PY=/root/NODOZE-pruning-release/.venv-cross-domain/bin/python
export PYTHONPATH=.
export OPENBLAS_NUM_THREADS=1
export OMP_NUM_THREADS=1

if [[ "${1:-}" == "--check" ]]; then
  "$PY" scripts/audit_budget_evidence_inputs.py --dry-run
  "$PY" scripts/run_budget_evidence_v7.py --case 0 --output-dir /tmp/budget-evidence-v7-dry-run --dry-run
  exit 0
fi
if [[ $# -ne 2 ]]; then
  echo "usage: $0 OUTPUT_ROOT NEW_DOCS_DIR  (or --check)" >&2
  exit 2
fi
RUN_ROOT=$1
DOC_ROOT=$2
if [[ -e "$RUN_ROOT" || -e "$DOC_ROOT" ]]; then
  echo "Both output paths must be new and absent" >&2
  exit 2
fi
mkdir -p "$RUN_ROOT" "$DOC_ROOT/logs"
cp docs/budget-evidence-v7/input_audit.json "$DOC_ROOT/input_audit.json"
for CASE in 0 1 2 3 4; do
  "$PY" scripts/run_budget_evidence_v7.py --case "$CASE" --output-dir "$RUN_ROOT" 2>&1 | tee "$DOC_ROOT/logs/run_case${CASE}.log"
done
"$PY" scripts/evaluate_budget_evidence_v7.py --input-dir "$RUN_ROOT" --output "$DOC_ROOT/results.json" 2>&1 | tee "$DOC_ROOT/logs/evaluate.log"
"$PY" scripts/diagnose_budget_evidence_v7.py --input-dir "$RUN_ROOT" --output-dir "$DOC_ROOT" --oracle-time 20 2>&1 | tee "$DOC_ROOT/logs/diagnose.log"
"$PY" scripts/diagnose_group_rank_v7.py --case 2 --input-dir "$RUN_ROOT" --output "$DOC_ROOT/theia1_group_rank.json" 2>&1 | tee "$DOC_ROOT/logs/theia1_group_rank.log"
"$PY" scripts/report_budget_evidence_v7.py --input-dir "$RUN_ROOT" --output-dir "$DOC_ROOT" 2>&1 | tee "$DOC_ROOT/logs/report.log"
"$PY" - "$RUN_ROOT" <<'PY'
import gzip,json,sys
from pathlib import Path
fresh=Path(sys.argv[1]);frozen=Path('/root/NODOZE-pruning-release/output/tc/budget-evidence-v7-r2')
for case in range(5):
    for src in sorted((frozen/f'case{case}'/'selections').glob('*.json.gz')):
        with gzip.open(src,'rt') as f:a=json.load(f)
        with gzip.open(fresh/f'case{case}'/'selections'/src.name,'rt') as f:b=json.load(f)
        for key in ('status','selected_ids','anchor_ids'):
            if a[key]!=b[key]:raise SystemExit(f'reproduction differs: {src.name} {key}')
print('PASS: all 120 frozen statuses, selected IDs and anchor IDs match')
PY
cp docs/budget-evidence-v7-r2/report.md docs/budget-evidence-v7-r2/missing_artifacts.md docs/budget-evidence-v7-r2/reproduce.sh "$DOC_ROOT/"
printf '\nThis report reproduces the frozen decisions; its elapsed-time statements refer to the original five processes. See this run\x27s profiles.csv for its own times.\n' >> "$DOC_ROOT/report.md"
echo "Completed outputs: $RUN_ROOT and $DOC_ROOT"
