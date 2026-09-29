# Multi-POI and Window Study Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or superpowers:subagent-driven-development. User explicitly authorized autonomous execution.

**Goal:** Separate candidate-window loss from POI loss, test reliability-calibrated rarity and adaptive multiple investigation anchors on available E3 providers, and register E5 readiness honestly.

**Architecture:** Read-only bounded candidate reader feeds a label-free scoring/POI module. A frozen decision runner writes exact selections before an offline evaluator opens references. The existing v1 runner and frozen evidence remain unchanged.

**Tech Stack:** Python/SQLite/numpy, existing diffusion and strict temporal witness selectors, matplotlib.

**Spec:** docs/superpowers/specs/2026-09-29-chain-workbench-v2-design.md

## Global Constraints

- No reference file or positive IDs are parameters of candidate building, POI selection or scoring.
- Fixed raw budgets [256,1024,4096], plus ratio curves [.01,.02,.05,.1,.2,.5,1] where feasible.
- Original POIs remain protected; single-anchor ablation uses earliest declared anchor deterministically.
- All known cases are development unless an independently unseen case is established; missing E5 logs cannot yield attack-retention claims.
- Save parameters, source hashes, POI reasons, candidate stopping reasons and all failed cases.

## Review Focus

- Cold start returns legacy rarity instead of attenuating it without evidence.
- Identical/equal-time events cannot become additional causal support.
- More POIs can consume budget and worsen retrieval; infeasible budgets are explicit.
- Candidate expansion cannot silently exceed its cap or remove base rows.
- Larger windows cannot gain an unfair compression denominator; compare equal absolute budgets and record fixed-scope compression.

### Task 1: Bounded candidate expansion

**Files:** scripts/chain_workbench_inputs.py; tests/test_chain_workbench_inputs.py.
**Interfaces:** expand_candidate_window(database, base_rows, *, start_ns, end_ns, poi_event_ids, step_seconds=300, max_extension_seconds=900, boundary_seconds=60, max_events=300000) -> (rows, diagnostics).

- [ ] Test read-only source, exact time boundaries, base preservation, cap diagnostics, process cohort frontier trigger, no-trigger and timestamp validation using tiny SQLite fixtures.
- [ ] Implement indexed interval reads and batched semantic hydration; require existing indices. Initial cohort comprises declared POI process endpoints, extends only via admitted process-process interactions. Either boundary extends only when a cohort process is active in the last/first60s of the admitted interval; fixed steps/caps, no labels.
- [ ] Run focused tests; audit39 CADETS13 missing source events offline against old/new windows.

### Task 2: Reliability fusion and adaptive investigation anchors

**Files:** tc_pruning/adaptive_pois.py; tests/test_adaptive_pois.py.
**Interfaces:** reliability_rarity(raw, context, weight=.75) -> ndarray; select_adaptive_pois(rows, values, *, max_pois=8, episode_seconds=60, gain_threshold=.05) -> (mask, diagnostics).

- [ ] Pin cold-start exact fallback, high-confidence interpolation, invalid numerics and label independence.
- [ ] Implement Rnew=(1-.75*C)*R+.75*C*S. POI suggestions preserve declared seeds, rank observed evidence, diversify process/relation/time episodes, and stop by marginal new cohort coverage below5percent or max8; distinguish suggestions from detector alerts.
- [ ] Test deterministic ties and reorder, no duplicate episode selection, noisy high-frequency multiplicity and mandatory-POI over-cap rejection.

### Task 3: Frozen benchmark and offline assessment

**Files:** scripts/run_chain_workbench.py; scripts/evaluate_chain_workbench.py; configs/chain_workbench_v2.json; tests/test_chain_workbench.py.

- [ ] Freeze method/window/POI grid before labels; include original RASP, old context fusion, reliability fusion, diffusion-only and rarity-only under same candidate and raw cap. Compare single, declared multiple and adaptive suggested POIs. Include original vs bounded expanded candidate tracks.
- [ ] Persist immutable candidates, masks/scores, config and implementation hashes; export representative selections via retained_chains.
- [ ] Evaluate fixed reference chains plus incremental known-positive retention excluding supplied POIs; source/candidate/temporal/selection loss stages. Use known-positive retention only where full chains are unavailable; no precision with unknown negatives.
- [ ] Add E3 providers available from inventory, E5 admission report if only annotations exist; run quality matrix and synthetic adversarial tests, all parameter changes remain disclosed development iterations.
- [ ] Plot compression/whole-reference curves, equal-raw-budget comparison, POI sensitivity and candidate ceilings; publish aggregate result with real raw exports only local.

### Task 4: Workbench organization and validation

- [ ] Consolidate new outputs beneath output/research/chain-workbench-v2 and docs/chain-workbench-v2; create clear current/archived/data/reproduction index.
- [ ] Archive only assistant-owned obsolete generated results with compatibility symlinks; never relocate user source datasets or unknown work.
- [ ] Link retained-output viewer and reference evaluation, run full tests/browser and independent whole-branch review, then publish code and aggregate summaries.

历史截止冻结为初始窗口起点减去允许的最大后向扩展跨度（扩窗案例900秒）；所有POI与窗口轨道共享该截止，防止后向扩展事件进入训练历史。
