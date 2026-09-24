# Cross-domain comparison implementation plan

> Execution: superpowers:executing-plans, inline in existing isolated research worktree.

Goal: implement coverage pruning and run pinned open-source baseline components on five frozen cases.
Spec: ../specs/2026-09-24-cross-domain-comparison-design.md

- [x] Record primary literature/code provenance; isolate pinned pcst_fast and NetworKit dependencies.
- [x] Failing behavioral tests then coverage selector and baseline adapters in separate modules.
- [x] Runner: common inputs/budgets/context tracks, repeat timing, random seeds; separate evaluator.
- [x] Freeze code/config; execute five cases and POI robustness.
- [x] Audit selected IDs/cost/POIs; performance tables/curves and experimental recommendations.
- [x] Full tests and independent review; fix important issues, rerun affected work, commit artifacts.

Review focus: adapters are not full-paper reproductions; raw cost never replaced by collapsed cost; labels do not enter selection; undirected connectivity is not temporal validity; RNG repetitions are not independent attacks.

Completion evidence: v2 664 decisions, 619 evaluated / 45 infeasible; 25 fresh-process matches; 605 tests passed. Independent review verified 404 report table cells and PCST runtime attribution. No universal superiority claim; see ../../cross-domain-study.md.
