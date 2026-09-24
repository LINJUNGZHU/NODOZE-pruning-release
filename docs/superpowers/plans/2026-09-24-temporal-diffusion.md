# Temporal diffusion implementation plan

> Execution: superpowers:executing-plans, inline; user's continuing no-question authorization applies.

Goal: diagnose losses, implement time-conditioned frequency diffusion and compare against graph kernels and existing methods.
Spec: ../specs/2026-09-24-temporal-diffusion-design.md

- [x] Diagnose THEIA1 miss ranks/reachability; read primary heat-kernel source.
- [ ] Test kernels and ranking invariants before implementation: tests/test_temporal_diffusion.py.
- [ ] Implement tc_pruning/temporal_diffusion.py: temporal_affinity(timestamp,poi_times,scale_ns), heat_walk(a,b,p,seed,time,tolerance), temporal_score(data,config,scale_ns,frequency,contrast), plain_score(data,config,kernel), stratified_budget(values,relations,mandatory,budget,ties).
- [ ] Freeze config and source; scripts/run_temporal_comparison.py writes v3 reports including diagnostic-independent selections; use existing evaluator with explicit time attribution extensions.
- [ ] Five-case comparison: old/public kernels, new diffusion, ablations and 30/300/3000 s sensitivity; two tracks/four budgets. Reuse v2 decision files only with manifest verification and unchanged method inputs.
- [ ] Independent evaluation; primary 1024 table + curves, POI deletion, source classification and limitations. If revision warranted by failures, freeze a separately named revision before rerunning.
- [ ] Full tests, independent review, fix important issues, commit results.

Review focus: labels absent from selection; old scores cannot contaminate POI deletion; all raw costs charged; public PCST receives new score too; no paper-reproduction or held-out claims. Scope is offline investigation, temporal proximity is not causality.
