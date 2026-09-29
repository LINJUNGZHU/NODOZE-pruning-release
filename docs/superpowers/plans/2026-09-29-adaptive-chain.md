# Adaptive chain pruning implementation plan

> Apply executing-plans with parallel independent components and test-driven-development. User explicitly requests autonomous implementation.

**Goal:** contextual rarity and whole-chain-aware graph compression with honest chain metrics and HTML.
**Architecture:** independent history model, observable-chain selector, offline chain evaluator, frozen sweep runner, static interactive results dashboard.
**Tech Stack:** Python, NumPy, pytest, existing Flask static assets, vanilla JS, Matplotlib.
**Spec:** docs/superpowers/specs/2026-09-29-adaptive-chain-design.md

## Global constraints
No GT in online methods. Strict timestamp order and original event identity. Raw-event budgets; no silent overflow. Preserve existing uncommitted work. No independent chain GT => NA.

## Review focus
Equal-time paths; missing source events; zero-denominator metrics; candidate-boundary truncation; budget/POI infeasibility.

### Task 1: Contextual history model
- [x] RED: contextual novelty, cold start, strict cutoff and weighted history tests.
- [x] Implement ContextualRarityModel.fit/history-only and score_rows in tc_pruning/contextual_rarity.py.
- [x] GREEN: tests/test_contextual_rarity.py.

### Task 2: Strict chain evaluation
- [x] RED: branches/bridges/time/source/provenance/funnel tests.
- [x] Implement evaluate_chains and evaluate_event_funnel in tc_pruning/chain_evaluation.py.
- [x] GREEN: tests/test_chain_evaluation.py.

### Task 3: Adaptive whole-chain selector and sweep
- [x] RED: full observed continuation, hard cap, truncation and label isolation tests.
- [x] Implement tc_pruning/adaptive_chains.py and scripts/run_adaptive_chains.py; freeze selection before opening annotations.
- [x] GREEN: selector and runner tests; replay CADETS and synthetic benchmark; generate JSON/CSV/PDF/PNG with fixed parameters.

### Task 4: HTML and final verification
- [x] Add chain-study HTML/CSS/JS and research entry link.
- [x] Validate in browser: curve, counts, chain events, missing evidence and budget interaction.
- [x] Run full pytest, independent review, compare baseline at actual compression.
- [x] Prepare the tested task-only branch for GitHub publication; final publication is recorded by Git history.
