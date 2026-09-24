# Temporal diffusion implementation plan

> Execution: superpowers:executing-plans, inline; user's continuing no-question authorization applies.

Goal: diagnose losses, implement time-conditioned frequency diffusion and compare against graph kernels and existing methods.
Spec: ../specs/2026-09-24-temporal-diffusion-design.md

- [x] Diagnose THEIA1 miss ranks/reachability; read primary heat-kernel source.
- [x] Test kernels and ranking invariants before implementation: tests/test_temporal_diffusion.py.
- [x] Implement tc_pruning/temporal_diffusion.py: temporal_affinity(timestamp,poi_times,scale_ns), heat_walk(a,b,p,seed,time,tolerance), temporal_score(data,config,scale_ns,frequency,contrast), plain_score(data,config,kernel), stratified_budget(values,relations,mandatory,budget,ties).
- [x] Freeze config and source; scripts/run_temporal_comparison.py writes v3 reports including diagnostic-independent selections; use existing evaluator with explicit time attribution extensions.
- [x] Five-case comparison: old/public kernels, new diffusion, ablations and 30/300/3000 s sensitivity; two tracks/four budgets. Reuse v2 decision files only with manifest verification and unchanged method inputs.
- [x] Independent evaluation; primary 1024 table + curves, POI deletion, source classification and limitations. If revision warranted by failures, freeze a separately named revision before rerunning.
- [x] Full tests, independent review, fix important issues, commit results.

Review focus: labels absent from selection; old scores cannot contaminate POI deletion; all raw costs charged; public PCST receives new score too; no paper-reproduction or held-out claims. Scope is offline investigation, temporal proximity is not causality.

Execution ledger: frozen v1 5a8b255, v2 5b59391, v3 b020f19, v4 b726e65. Rulings and reasons are in the spec extensions. v4 final table: 2072 decisions,1937 evaluated,135 infeasible; source/config audit,616 pytest,55 fresh-process matches. Independent review of kernels/typed allocator/witness heap passed; final report tables/metrics/counts/profiles checked against JSON; PCST award naming corrected. User no-question authorization: keep existing research branch/worktree; no merge or publish. No global default change due low-budget and missing-POI regressions.
