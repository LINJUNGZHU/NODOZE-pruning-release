# v7-r2 execution record

All five runner processes exited 0 and wrote 24 selections each to `/root/NODOZE-pruning-release/output/tc/budget-evidence-v7-r2/`. They were run sequentially. `case0` was run first; a later shell loop ran `case1` through `case4`. Independent evaluation then exited 0 after verifying each saved decision and legal time certificate. The post-selection diagnosis exited 0 with 120 mutually partitioned stage rows and 20 optimal finite-pool MILP rows. The THEIA1 group-rank audit and report generator also exited 0. The case manifest SHA-256, per-selection and pool SHA-256, process times and RSS are persisted in `source_manifest.json`, the external case manifests and `profiles.csv`. Original terminal stdout was observed in the research session but not saved as standalone raw log files; `reproduce.sh` captures logs for a fresh run.

```bash
export PYTHONPATH=. OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
PY=/root/NODOZE-pruning-release/.venv-cross-domain/bin/python
"$PY" scripts/run_budget_evidence_v7.py --case 0 --output-dir /root/NODOZE-pruning-release/output/tc/budget-evidence-v7-r2
for CASE in 1 2 3 4; do
  "$PY" scripts/run_budget_evidence_v7.py --case "$CASE" --output-dir /root/NODOZE-pruning-release/output/tc/budget-evidence-v7-r2
done
"$PY" scripts/evaluate_budget_evidence_v7.py --input-dir /root/NODOZE-pruning-release/output/tc/budget-evidence-v7-r2 --output docs/budget-evidence-v7-r2/results.json
"$PY" scripts/diagnose_budget_evidence_v7.py --input-dir /root/NODOZE-pruning-release/output/tc/budget-evidence-v7-r2 --output-dir docs/budget-evidence-v7-r2 --oracle-time 20
"$PY" scripts/diagnose_group_rank_v7.py --case 2 --input-dir /root/NODOZE-pruning-release/output/tc/budget-evidence-v7-r2 --output docs/budget-evidence-v7-r2/theia1_group_rank.json
"$PY" scripts/report_budget_evidence_v7.py --input-dir /root/NODOZE-pruning-release/output/tc/budget-evidence-v7-r2 --output-dir docs/budget-evidence-v7-r2
```

`source_manifest.json` records execution HEAD `44323282e36926248d488221bdb25f3b17b097f9`; the SHA-256 of each actual runner dependency is authoritative. The evaluator and diagnosis versions are recorded separately. `reproduce.sh --check` verifies CLI availability without writing files. Full reproduction requires two new output paths and compares the 120 selected ID sets with this frozen round before copying the published narrative.
