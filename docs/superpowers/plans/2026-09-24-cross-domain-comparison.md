# Cross-domain comparison implementation plan

> Execution: superpowers:executing-plans, inline in existing isolated research worktree.

Goal: implement coverage pruning and run pinned open-source baseline components on five frozen cases.
Spec: ../specs/2026-09-24-cross-domain-comparison-design.md

- [ ] Record primary literature/code provenance; isolate pinned pcst_fast and NetworKit dependencies.
- [ ] Failing behavioral tests then coverage selector and baseline adapters in separate modules.
- [ ] Runner: common inputs/budgets/context tracks, repeat timing, random seeds; separate evaluator.
- [ ] Freeze code/config; execute five cases and POI robustness.
- [ ] Audit selected IDs/cost/POIs; performance tables/curves and experimental recommendations.
- [ ] Full tests and independent review; fix important issues, rerun affected work, commit artifacts.

Review focus: adapters are not full-paper reproductions; raw cost never replaced by collapsed cost; labels do not enter selection; undirected connectivity is not temporal validity; RNG repetitions are not independent attacks.
