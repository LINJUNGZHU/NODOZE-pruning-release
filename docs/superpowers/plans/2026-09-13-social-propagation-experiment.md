# Social propagation experiment implementation plan

**Goal:** Measure whether relation-balanced temporal source/fork propagation improves positive-entity retention over frozen RASP-D at identical candidate/POI/budget inputs.
**Spec:** `docs/social-propagation-study.md`; user authorized immediate experiments.
**Architecture:** New label-free scorer and witness builder, isolated benchmark runner, immutable decision exports, then independent CSV/SQLite evaluation. Existing production algorithms unchanged.
**Execution:** Inline in `/root/NODOZE-social-experiment`; no delegation needed.

## Fixed protocol

- Four cases allowed for `positive_node_retention` in `configs/benchmark-admission.json`; OPTC and unavailable cases excluded.
- Same frozen ledgers, analyst POIs, budgets 5%, 10%, 20%; these are reused development cases, not independent testing.
- Primary variant: geometric mean of RASP and relation-balanced temporal scores, new max-product witnesses, same q=0 diverse selector.
- Ablations: RASP baseline; temporal uniform channel weights; temporal relation weights with old witnesses; temporal relation weights with new witnesses. No parameters selected using current labels.
- Channel mass: maximum rarity-floor weight per directed endpoint/relation family; equally split mass over a node's relation types, normalize within each type. Compute outgoing and incoming normalizations separately.
- Temporal messages minimize additive negative-log channel cost with per-event survival 0.85. Reverse scan starts from POIs; forward scan can fork from a reverse witness. Equal timestamp groups read state before any group writes.
- Score `1/(1+cost)`, finite cost only; not a calibrated probability. No attack classifier or deep-learning reproduction claims.

## Tasks

- [x] Write `tests/test_social_propagation.py`: strict times, reverse/fork witnesses, direction, duplicate/permutation invariance, relation normalization, complete path budgets; run failing tests.
- [x] Implement `tc_pruning/social_propagation.py`: `channel_weights(src,dst,relation,rarity,balanced=True)` and `temporal_propagation(src,dst,timestamp,poi,forward_weight,reverse_weight,tie,survival=.85) -> (score,backward,parent,pivot)`; validate input, test again.
- [x] Implement `scripts/run_social_propagation.py`, one subprocess per case; compute and freeze every variant before reading labels; save selected IDs, scores, timing, hash/config evidence. Independent evaluator queries read-only SQLite for events between CSV-positive endpoints in the original declared scope.
- [x] Verify replayed baseline against saved selected IDs and denominator hashes against uploaded-groundtruth audit. Verify retained witness closure and strict timestamps, not merely count retained edges.
- [x] Run all four cases, retain all ablations/budgets, summarize macro and micro entity/event retention, process-positive subset, excluded POI nodes, time and per-process RSS. Export CSV/JSON/PNG and report negative results as well as improvements.
- [x] Run relevant regression tests; update README, commit, integrate and push only this task's files.

Exploratory follow-up: after the first three CADETS results, fixed reserve fractions 0.1 and 0.25; included every fraction/budget/case. Final four-case rerun uses one source version. Two evaluation-tool issues fixed and regression-tested; no score or truth denominator tuning.
