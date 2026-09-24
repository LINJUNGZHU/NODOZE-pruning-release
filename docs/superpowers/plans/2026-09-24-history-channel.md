# History/channel Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline.

**Goal:** Implement historical conditional calibration and channel retrieval and test against frozen baselines.
**Architecture:** Read-only historical builder -> cached aligned rarity -> unchanged diffusion -> channel pooling -> raw witness selection -> separate evaluator.
**Tech Stack:** Python, SQLite, NumPy, SciPy/HiGHS, existing venv.
**Spec:** ../specs/2026-09-24-history-channel-design.md

## Global Constraints
- No evaluation labels, case-specific event IDs/names, or external alerts in selection.
- Existing frozen modules and decisions remain immutable; new files only.
- Five development cases, primary1024, raw caps64/256/1024/4096, two tracks.
- User authorizes autonomous implementation; preserve isolated research branch.

## Review Focus
- Future timestamps/cold history: fit/calibration split tests and fallback.
- Host/semantic separation: identical names across hosts never share counts.
- Duplicate and boundary times: count occupied minutes; bounded total episode span.
- Expanded pool eligibility/cap/mandatory/witness accounting: synthetic tests.
- Incumbent/cached input/source provenance: inherited verification plus cache hashes.

## Tasks
1. [ ] Write failing tests for conditional probability, monotone weighted ECDF,
   host separation, cold start, SQL time splits/occupied buckets, cross-relation
   bounded groups and pool expansion. Implement new history_channel module.
2. [ ] Add history preparation, v6 config/runner, profile and evaluator wiring.
   Run full suite and freeze before case evaluation; no label-dependent tuning.
3. [ ] Build five history caches, run five-case main and controls, separate
   evaluator and new-process profiles; diagnose pool losses only afterward.
4. [ ] Publish complete CSV/JSON/figures and honest comparisons; independent
   whole-change review, necessary fixes and final verified commit.

Interfaces: historical builder writes rarity array aligned by ledger ID hash and
split diagnostics. New selectors accept only arrays/routes, no reference path.
Parent reports/source hashes preserved. Historical preparation never opens labels.
