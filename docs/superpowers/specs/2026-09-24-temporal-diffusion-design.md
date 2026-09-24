# POI-conditioned temporal diffusion comparison

User authorizes autonomous continued optimization, especially comparisons. Preserve frequency statistics and diffusion; same five ledgers, POIs, partial reference and raw-event budgets. Existing worktree b81598a is clean. No external alerts, new oracle seeds, attack-specific strings or labels in selectors.

Diagnosis: THEIA1 missing 225 positives are temporally reachable: CONNECT/SEND rank ~69500, 223 RECV rank ~280300. Static channel diffusion assigns similar scores to activity at different times. These five cases are development data, including this diagnosis.

Alternatives: (1) time rerank only (cheap baseline); (2) time-conditioned transition and background diffusion (primary); (3) relation-stratified allocation (baseline). GNN deferred: no independent training corpus in scope.

Primary temporal_top: for each POI at time t, event affinity h=1/(1+abs(event_time-t)/tau), tau=300 seconds, applied to conductance both inside transition and final event score. Preserve frozen historical rarity, semantic uniqueness, relation-balanced duplicate-invariant channels, POI/background lift, endpoint mix .5, escape floor 1e-6. Background is recomputed on each seed's weighted graph. Each seed result normalized before max merge; POIs mandatory. Compare tau=30 and 3000 seconds as disclosed sensitivity, not per-case selected parameters.

Controls: frozen diffusion_top, coverage_semantic, localdegree_top and pcst_native/random from v2 with exact ledger/config/source hashes; rerun old diffusion for equality. New baselines time_rerank, relation_stratified, plain PPR, heat kernel t=3, plus temporal_episode and temporal_no_frequency/no_contrast. Plain PPR/HK are own formula implementations on unweighted duplicate-invariant undirected channels, geometric endpoint relevance, max over POIs: kernel/task adapters, not whole-paper reproductions. HK reference: Kloster & Gleich KDD2014, Poisson-series definition; verify small-matrix exponential. Public PCST adapter also receives temporal prizes (same fixed 14 multipliers) to avoid handicapping baseline to old scores.

Raw budgets 64/256/1024/4096, both poi_only and shared_context. Main budget 1024. Separate label-free selection from evaluation. Record code/input hashes, times, output IDs, actual costs and structural metrics. POI deletion at 1024 for baseline/primary/rerank. Reference and labels never change.

Tests: monotone affinity/shift invariance; distant duplicate activity loses priority; complete mass/dangling HK; no host crossing by shared integer nodes; mandatory cap/stratification; no-frequency ablation. Full tests and independent final review required. Default algorithm unchanged until evidence justifies replacement. Numerical validation not a whole-paper reproduction.

## Development extension v2

Early completed v1 FD1/FD3/TRACE5 cases show relation_stratified TP 21/15/30 vs static diffusion 18/13/28, temporal_top 18/13/29. Freeze an explicit follow-up before evaluating its outputs: primary typed_temporal uses the identical stratified allocator with temporal_score; compare to old relation_stratified and pure time-only allocation. Add degree-normalized PPR/HK adapters consistent with literature's degree-normalization step (still no conductance sweep/full paper reproduction). Ablate frequency/contrast, and fixed tau 30/3000 sensitivity. No per-case parameter winners. All v1 outputs retained unchanged; v2 copies them with provenance and validates shared configuration. Main tables keep both v1 primary and v2 primary. This remains development iteration, not independent confirmation.
