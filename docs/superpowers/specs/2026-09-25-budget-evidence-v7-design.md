# Budget evidence v7 first-stage design

## User intent and boundaries

Given a frozen event ledger, report-derived oracle POIs and raw ledger-event cap B, return selected event IDs with explicit legal temporal witnesses, and distinguish candidate loss, scoring loss, path cost and objective competition. This first stage implements P0 input/regression audit, P1 retrieval representations and P2 fixed-pool witnesses/objectives. P3 context frequency and state diffusion remain a separately designed experiment. These five cases are a development set. No default CLI/web replacement, data download, GPU training or large logs in Git.

## Verified environment and input contract

The isolated linked worktree is `/root/NODOZE-pruning-release/.worktrees/sparse-five-case-study`, HEAD `f6fa89d`, initially clean. Python `/root/NODOZE-pruning-release/.venv-cross-domain/bin/python`; NumPy 1.26.4, SciPy 1.14.1, pcst_fast 1.0.10, NetworKit 11.2.2. Baseline 662 tests pass. All five ledger, history cache and v6 reports exist and their ledger hashes match. `docs/budget-evidence-v7/input_audit.json` records hashes and paths. The algorithm reads no local reference; only independent evaluation/diagnosis reads `docs/sparse-five-local-critical-reference.json`. Metadata time safety remains `unverified`.

Frozen `frequency_diffusion.load_ledger` supplies arrays `src,dst,relation,timestamp,rarity,poi,tie,ids` with host-qualified nodes. All ledger IDs, including `LINEAGE:` synthetic edges, count toward B; the output reports CDM and synthetic separately. Duplicate event IDs are input errors. `rasp.temporal_routes` and `temporal_fork_routes` enforce strict equal-time treatment using stable input order. Old fork witness is alternative 0. Alternate 1/2 derive from the existing strict upstream/downstream route parents, not a claimed global k-shortest procedure.

## Architecture and interfaces

- `candidate_views.py`: `rank_views(primary, rarity, temporal, ties, policy, rrf_c)` returns deterministic event order and per-view ranks. Policies: primary, round_robin, rrf. Scores nonnegative; ties use frozen IDs.
- `deferred_event_groups.py`: `GroupIndex.from_events(data, window_ns, relation_policy)` stores compact group descriptors and sorted member indices. Group key is host-qualified actual unordered endpoint pair, optionally relation; every group has total span <=10s. Group score is max member score. Group policy yields descriptors whose members are requested lazily; no member is free.
- `alternative_witnesses.py`: `witnesses(anchor, routes, k)` returns up to k de-duplicated tuples of event indices; `k=1` exactly matches the old fork bundle. Each accepted chain is validated for strict time direction and host-isolated graph endpoints; certificates carry anchor, events, rule and digest.
- `evidence_objective.py`: fixed `CandidateSnapshot` (candidate anchor IDs, group IDs, k-path certificates, materialized union, score, hashes) and `select(snapshot, mandatory, B, objective, eta)` returning selected original events, explicit selected anchors/certificates and objective. Greedy recomputes true union cost. Objectives are `edge_score`, `anchor_score`, `witness_plus_detail`; latter uses OR-of-AND group support with normalized group max scores plus eta times normalized selected-anchor scores. Positive zero-cost actions apply once.
- `scripts/audit_budget_evidence_inputs.py`: repeatable read-only audit writer with source/input hashes, baseline map and status.
- `scripts/run_budget_evidence_v7.py`: case-level label-free runner, E0/E2/E3 configurations and atomic outputs; `--dry-run` lists work only. Reuses verified v6 inputs and histories. All `selection` and `witness` files include hashes and are published before independent evaluation.
- `scripts/evaluate_budget_evidence_v7.py`: verifies source/config/selection hashes, budgets, mandatory set, path certificates and ID closure; computes local partial-positive proxy, group any/full, incremental recall, structure and statuses.
- `scripts/diagnose_budget_evidence_v7.py`: post-selection stage audit and finite-pool label oracle; no diagnostic ID feeds back.
- `scripts/profile_budget_evidence_v7.py`: separate-process runtime/RSS for selected core comparisons, including cold/warm scopes.
- `scripts/report_budget_evidence_v7.py`: registry, tables, plots, source/baseline manifests, missing artifacts and reproduction script.

`Event` is represented by the frozen ledger arrays plus `ids`; `GroupRef` by integer group, member slice and time bounds; `Witness` by anchor, ordered rule, unique event index tuple and hash; `CandidateSnapshot` by actual executable actions, generated certificates, union of materialized event IDs and hash; `Selection` by selected IDs, explicit anchors/certificate IDs, actual cost, status and hashes. JSON serialization keeps string IDs; event indices are internal only.

## Core experiment matrix and resources

E0: v4 and v6 portfolio, five cases x B=256/1024 =20 regressions; compare selected ID sets with frozen reports. E2: event/group representation x single/multiview =4, five cases, B=256/1024 =40 runs, cap of 32768 distinct materialized ledger IDs including witnesses. E3: k=1/3 x three objectives, five cases, B=256/1024 =60 decisions over a frozen actual candidate snapshot per k. Thus 120 predeclared core configurations. Sensitivities are separate: RRF c=10/60/100; cap 4096/8192/16384/32768/65536 at B1024; eta=0/.25/1/4; k5. Full four-budget, shared-context, robustness and P3 only after core results and resource check. A case process loads its large ledger once and reuses score/routes across configurations; no case parallelism in profiling. Initial resource envelope: <=8 GiB RSS per process, <=2 concurrent cases, 20-second MILP as historical baseline, 4-hour wall-time checkpoint for 120 core decisions. These are caps/targets, not measured costs; one pilot case records actual time/RSS before full run.

Candidate fairness: report group descriptors, potential members, executable anchors, generated certificates, actual materialized union, build time and RSS. Candidate-closure label coverage is post-selection diagnosis, and cannot be called budgeted recall. Equal cap compares actual materialized IDs, with descriptor overhead reported separately. E3 freezes per-k pool hash; no new actions during objective comparisons.

## Evaluation and safety rules

Hard cap counts unique ledger IDs. Mandatory items must be present; `|M|>B` yields `infeasible_mandatory_budget` and null metrics. `poi_only` is primary; shared context uses identical pre-existing semantic continuations for every method and is separate. Report POI is oracle, not automatic detection. For POI deletion, `t0` remains the original earliest POI. Labels are a partial-positive local proxy; official-equivalent FP/FN/P/R/F1 remain null. No case-specific IDs, report fields or label-derived rules enter the runner.

Small-graph property tests cover union cost, AND/OR support, strict time, host isolation, bounded groups, duplicates, infeasible, zero-cost actions, cache invalidation, label isolation and exact-vs-greedy objective. No theoretical approximation ratio is claimed for the path-union/AND problem. Outputs never overwrite existing files; changes in input, config, route or source hash invalidate reuse. Existing v6 files remain frozen.

## Expected interpretation

H1 is supported only if actual materialized-closure recall improves under matched resources and selection translates part of it into final coverage. H2 needs same-pool comparisons. H3 and H4 remain open until their separate experiments. Negative results, per-case regressions and absent artifacts remain explicit.
